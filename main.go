package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/schollz/progressbar/v3"
)

var password string
var copy bool
var expiresString string
var expires int64
var filename string
var serverUrl string
var suppressOutput bool

var encryptedFilename string = "v8p.me-cli.tmp"

const (
	iterations = 100000
	chunkSize  = 1 * 1000 * 1000 // 1mb per chunk
	saltSize   = 16
	nonceSize  = 12
)

func main() {
	log.SetFlags(0)

	customFilename := ""
	dryFilename := ""

	const serverUsage = "directs requests to a custom server instead of default of https://v8p.me (-s <url>)"
	flag.StringVar(&serverUrl, "server", "https://v8p.me", serverUsage)
	flag.StringVar(&serverUrl, "s", "https://v8p.me", serverUsage)

	const copyUsage = "copy the resulting url to the clipboard (-c)"
	flag.BoolVar(&copy, "copy", false, copyUsage)
	flag.BoolVar(&copy, "c", false, copyUsage)

	const passwordUsage = "enable encryption and set a password (-p <password>)"
	flag.StringVar(&password, "password", "", passwordUsage)
	flag.StringVar(&password, "p", "", passwordUsage)

	const expiresUsage = "set the expiry date after which the file should be deleted (-e 1d), (-e 3 weeks), (-e 5 m)"
	flag.StringVar(&expiresString, "expires", "0m", expiresUsage)
	flag.StringVar(&expiresString, "e", "0m", expiresUsage)

	const filenameUsage = "override filename sent to server"
	flag.StringVar(&customFilename, "filename", "", filenameUsage)
	flag.StringVar(&customFilename, "f", "", filenameUsage)

	const quietUsage = "suppress all output except the URL"
	flag.BoolVar(&suppressOutput, "quiet", false, quietUsage)
	flag.BoolVar(&suppressOutput, "q", false, quietUsage)

	const dryUsage = "skip upload and save encrypted file to disk as specified filename"
	flag.StringVar(&dryFilename, "dry", "", dryUsage)
	flag.StringVar(&dryFilename, "d", "", dryUsage)

	flag.Usage = func() {
		printUsage()
	}

	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		log.Println("error: no filename provided.")
		printUsage()
		return
	}

	if suppressOutput {
		log.SetOutput(io.Discard)
	}

	if len(dryFilename) > 0 {
		encryptedFilename = dryFilename
	}

	expires, err := parseExpiry(expiresString)
	if err != nil {
		log.Println("error: could not parse expiry")
		printUsage()
		return
	}

	filename = args[len(args)-1]

	info, err := os.Stat(filename)
	if err != nil {
		log.Println("error occured:", err.Error())
		return
	}

	serverFilename := info.Name()

	if len(customFilename) > 0 {
		serverFilename = customFilename
	}

	if len(password) > 0 {
		bar := progressbar.NewOptions(int(info.Size()),
			progressbar.OptionShowBytes(true),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetVisibility(!suppressOutput),
			progressbar.OptionSetDescription("[cyan][1/2][reset] encrypting file..."))

		err := encryptFile(filename, password, bar)
		log.Println()
		if err != nil {
			log.Println("error occured:", err.Error())
			return
		}
		log.Println()

		if len(dryFilename) > 0 {
			log.Println("encryption complete!")
			return
		}
		log.Println("encryption complete! initializing upload...")

		newInfo, err := os.Stat(encryptedFilename)
		if err != nil {
			log.Println("error occured:", err.Error())
			return
		}

		bar = progressbar.NewOptions(int(newInfo.Size()),
			progressbar.OptionShowBytes(true),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowTotalBytes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetVisibility(!suppressOutput),
			progressbar.OptionSetDescription("[cyan][2/2][reset] uploading file..."))

		downloadUrl, err := streamFileUpload(encryptedFilename, serverUrl+"/api", info, serverFilename, true, int(expires), bar)
		if err != nil {
			log.Println("error occured:", err.Error())
			return
		}
		log.Print("\033[1m")
		fmt.Printf("%s", downloadUrl)
		log.Print("\033[0m")

		err = os.Remove(encryptedFilename)
		if err != nil {
			log.Println("error while deleting file:", err.Error())
			return
		}
	} else {
		bar := progressbar.NewOptions(int(info.Size()),
			progressbar.OptionShowBytes(true),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowTotalBytes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetDescription("[cyan][1/1][reset] uploading file..."))

		downloadUrl, err := streamFileUpload(filename, serverUrl+"/api", info, serverFilename, false, int(expires), bar)
		log.Println()
		if err != nil {
			log.Println("error occured:", err.Error())
			return
		}
		log.Println("upload complete!")
		log.Printf("%s\033[0m\n", downloadUrl)
	}
}

func streamFileUpload(filePath, apiPath string, ogFileInfo os.FileInfo, serverFilename string, encrypted bool, expires int, bar *progressbar.ProgressBar) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return "", err
	}

	reader := io.TeeReader(file, bar)

	req, err := http.NewRequest("POST", apiPath, reader)
	if err != nil {
		return "", err
	}

	ext := filepath.Ext(serverFilename)
	fileType := mime.TypeByExtension(ext)
	if len(fileType) == 0 {
		fileType = "application/octet-stream"
	}

	encryptedStr := "0"
	if encrypted {
		encryptedStr = "1"
	}

	req.Header.Set("X-File-Name", url.QueryEscape(serverFilename))
	req.Header.Set("X-File-Type", fileType)
	req.Header.Set("X-File-Size", strconv.Itoa(int(ogFileInfo.Size())))
	req.Header.Set("X-Encrypted", encryptedStr)

	if expires > 0 {
		req.Header.Set("X-Expiration-Date", strconv.Itoa(expires+int(time.Now().Unix())))
	}
	req.Header.Set("Content-Length", strconv.Itoa(int(info.Size())))
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode >= 400 {
		return "", errors.New("unexpected error: " + resp.Status)
	}

	if copy {
		err := clipboard.WriteAll(serverUrl + "/" + string(respBody))
		if err != nil {
			return "", err
		}
		log.Println()
		log.Println()
		log.Println("upload complete!")
		log.Println("(wrote to clipboard)")
	}

	return serverUrl + "/" + string(respBody), nil
}

func encryptFile(filename string, password string, progressBar *progressbar.ProgressBar) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	outFile, err := os.Create(encryptedFilename)
	if err != nil {
		return err
	}
	defer outFile.Close()

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := outFile.Write(salt); err != nil {
		return err
	}

	key, err := deriveKey(password, salt, iterations)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	buf := make([]byte, chunkSize)
	for {
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		err = progressBar.Add(n)
		if err != nil {
			return err
		}

		if n == 0 {
			break
		}
		plaintext := buf[:n]

		nonce := make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}

		ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

		if _, err := outFile.Write(nonce); err != nil {
			return err
		}
		if _, err := outFile.Write(ciphertext); err != nil {
			return err
		}
	}

	return nil
}

func deriveKey(password string, salt []byte, iterations int) ([]byte, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func printUsage() {
	log.Println("usage: v8p [options] <filename>")
	log.Println()
	log.Println("options:")
	log.Println("  general:")
	log.Println("    --server,   -s <url>         set custom server instead of default (https://v8p.me)")
	log.Println("    --copy,     -c               automatically copy returned URL to clipboard")
	log.Println()
	log.Println("  security:")
	log.Println("    --password, -p <password>    enable encryption and set password")
	log.Println("    --expires,  -e <date str>    set expiry date of file (e.g., -e 1d, -e \"5 minutes\")")
	log.Println()
	log.Println("  upload behavior:")
	log.Println("    --filename, -f <name>        override filename sent to server")
	log.Println("    --dry,      -d <filename>    skip upload and save encrypted file to disk as specified filename")
	log.Println()
	log.Println("  output control:")
	log.Println("    --quiet,    -q               suppress all output except the URL")
	log.Println()
	log.Println("examples:")
	log.Println("v8p -c -p Password123! -e \"5 days\" image.png")
	log.Println("v8p --copy --password=\"Cr3d3nt1a1$\" text.txt")
	log.Println("v8p -e 1h -c video.mkv")
}

func parseExpiry(expiryStr string) (int64, error) {
	re := regexp.MustCompile(`^([\d.]+)\s*([a-zA-Z]+)$`)
	matches := re.FindStringSubmatch(strings.TrimSpace(expiryStr))
	if matches == nil {
		return 0, errors.New("could not parse expiry string: " + expiryStr)
	}
	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, err
	}
	unit := strings.ToLower(matches[2])
	var multiplier float64
	switch unit {
	case "m", "min", "mins", "minute", "minutes":
		multiplier = 60
	case "h", "hr", "hrs", "hour", "hours":
		multiplier = 3600
	case "d", "day", "days":
		multiplier = 86400
	case "w", "week", "weeks":
		multiplier = 604800
	case "mo", "month", "months":
		multiplier = 2629800
	case "y", "yr", "year", "years":
		multiplier = 31557600
	default:
		return 0, errors.New("unknown time unit: " + unit)
	}
	return int64(value * multiplier), nil
}
