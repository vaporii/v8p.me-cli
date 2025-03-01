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

const (
	iterations = 100000
	chunkSize  = 1 * 1000 * 1000 // 1mb per chunk
	saltSize   = 16
	nonceSize  = 12
)

func main() {
	customFilename := ""

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

	flag.Usage = func() {
		printUsage()
	}

	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("error: no filename provided.")
		printUsage()
		return
	}

	expires, err := parseExpiry(expiresString)
	if err != nil {
		fmt.Println("error: could not parse expiry")
		printUsage()
		return
	}

	filename = args[len(args)-1]

	info, err := os.Stat(filename)
	if err != nil {
		fmt.Println("error occured:", err.Error())
		return
	}

	if len(password) > 0 {
		bar := progressbar.NewOptions(int(info.Size()),
			progressbar.OptionShowBytes(true),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetDescription("[cyan][1/2][reset] encrypting file..."))

		err := encryptFile(filename, password, bar)
		fmt.Println()
		if err != nil {
			fmt.Println("error occured:", err.Error())
			return
		}
		fmt.Println()
		fmt.Println("encryption complete! initializing upload...")

		newInfo, err := os.Stat("v8p.me-cli.tmp")
		if err != nil {
			fmt.Println("error occured:", err.Error())
			return
		}

		bar = progressbar.NewOptions(int(newInfo.Size()),
			progressbar.OptionShowBytes(true),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowTotalBytes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetDescription("[cyan][2/2][reset] uploading file..."))

		downloadUrl, err := streamFileUpload("v8p.me-cli.tmp", serverUrl+"/api", info, true, int(expires), bar)
		fmt.Println()
		if err != nil {
			fmt.Println("error occured:", err.Error())
			return
		}
		fmt.Println("upload complete!")
		fmt.Printf("%s\033[0m\n", downloadUrl)

		err = os.Remove("v8p.me-cli.tmp")
		if err != nil {
			fmt.Println("error while deleting file:", err.Error())
			return
		}
	} else {
		bar := progressbar.NewOptions(int(info.Size()),
			progressbar.OptionShowBytes(true),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowTotalBytes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetDescription("[cyan][1/1][reset] uploading file..."))

		downloadUrl, err := streamFileUpload(filename, serverUrl+"/api", info, false, int(expires), bar)
		fmt.Println()
		if err != nil {
			fmt.Println("error occured:", err.Error())
			return
		}
		fmt.Println("upload complete!")
		fmt.Printf("%s\033[0m\n", downloadUrl)
	}
}

func streamFileUpload(filePath, apiPath string, ogFileInfo os.FileInfo, encrypted bool, expires int, bar *progressbar.ProgressBar) (string, error) {
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

	fileName := ogFileInfo.Name()
	ext := filepath.Ext(fileName)
	fileType := mime.TypeByExtension(ext)
	if len(fileType) == 0 {
		fileType = "application/octet-stream"
	}

	encryptedStr := "0"
	if encrypted {
		encryptedStr = "1"
	}

	req.Header.Set("X-File-Name", url.QueryEscape(fileName))
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

	messageText := ""
	if copy {
		err := clipboard.WriteAll(serverUrl + "/" + string(respBody))
		if err != nil {
			return "", err
		}
		fmt.Println()
		messageText = "(wrote to clipboard)\n\033[1m"
	}

	return messageText + serverUrl + "/" + string(respBody), nil
}

func encryptFile(filename string, password string, progressBar *progressbar.ProgressBar) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	outFile, err := os.Create("v8p.me-cli.tmp")
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
	fmt.Println("usage: v8p [options] <filename>")
	fmt.Println()
	fmt.Println("options:")
	fmt.Println("  general:")
	fmt.Println("    --server,   -s <url>         set custom server instead of default (https://v8p.me)")
	fmt.Println("    --copy,     -c               automatically copy returned URL to clipboard")
	fmt.Println()
	fmt.Println("  security:")
	fmt.Println("    --password, -p <password>    enable encryption and set password")
	fmt.Println("    --expires,  -e <date str>    set expiry date of file (e.g., -e 1d, -e \"5 minutes\")")
	fmt.Println()
	fmt.Println("  upload behavior:")
	fmt.Println("    --filename, -f <name>        override filename sent to server")
	fmt.Println()
	fmt.Println("  output control:")
	fmt.Println("    --quiet,    -q               suppress all output except the URL")
	fmt.Println()
	fmt.Println("examples:")
	fmt.Println("v8p -c -p Password123! -e \"5 days\" image.png")
	fmt.Println("v8p --copy --password=\"Cr3d3nt1a1$\" text.txt")
	fmt.Println("v8p -e 1h -c video.mkv")
}

func parseExpiry(expiryStr string) (int64, error) {
	re := regexp.MustCompile(`^([\d.]+)\s*([a-zA-Z]+)$`)
	matches := re.FindStringSubmatch(strings.TrimSpace(expiryStr))
	if matches == nil {
		return 0, fmt.Errorf("could not parse expiry string: %s", expiryStr)
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
		return 0, fmt.Errorf("unknown time unit: %s", unit)
	}
	return int64(value * multiplier), nil
}
