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

type config struct {
	serverUrl      string
	copy           bool
	password       string
	expiresString  string
	customFilename string
	dryFilename    string
	suppressOutput bool
	filePath       string
}

// encryption params
const (
	iterations = 100000
	chunkSize  = 1 * 1000 * 1000 // 1mb per chunk
	saltSize   = 16
	nonceSize  = 12
)

func parseFlags() (*config, error) {
	cfg := &config{}

	const serverUsage = "set custom server instead of default (https://v8p.me)"
	flag.StringVar(&cfg.serverUrl, "server", "https://v8p.me", serverUsage)
	flag.StringVar(&cfg.serverUrl, "s", "https://v8p.me", serverUsage)

	const copyUsage = "automatically copy returned URL to clipboard"
	flag.BoolVar(&cfg.copy, "copy", false, copyUsage)
	flag.BoolVar(&cfg.copy, "c", false, copyUsage)

	const passwordUsage = "enable encryption and set password"
	flag.StringVar(&cfg.password, "password", "", passwordUsage)
	flag.StringVar(&cfg.password, "p", "", passwordUsage)

	const expiresUsage = "set expiry date of file (e.g., -e 1d, -e \"5 minutes\")"
	flag.StringVar(&cfg.expiresString, "expires", "0m", expiresUsage)
	flag.StringVar(&cfg.expiresString, "e", "0m", expiresUsage)

	const filenameUsage = "override filename sent to server"
	flag.StringVar(&cfg.customFilename, "filename", "", filenameUsage)
	flag.StringVar(&cfg.customFilename, "f", "", filenameUsage)

	const dryUsage = "skip upload and save encrypted file to disk as specified filename"
	flag.StringVar(&cfg.dryFilename, "dry", "", dryUsage)
	flag.StringVar(&cfg.dryFilename, "d", "", dryUsage)

	const quietUsage = "suppress all output except the URL"
	flag.BoolVar(&cfg.suppressOutput, "quiet", false, quietUsage)
	flag.BoolVar(&cfg.suppressOutput, "q", false, quietUsage)

	flag.Usage = func() {
		printUsage()
	}

	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		return nil, errors.New("error: no filename provided")
	}
	cfg.filePath = args[len(args)-1]

	return cfg, nil
}

func main() {
	encryptedFilename := "v8p.me-cli.tmp"

	log.SetFlags(0)

	cfg, err := parseFlags()
	if err != nil {
		log.Println(err.Error())
		printUsage()
		return
	}

	if cfg.suppressOutput {
		log.SetOutput(io.Discard)
	}

	if len(cfg.dryFilename) > 0 {
		encryptedFilename = cfg.dryFilename
	}

	expires, err := parseExpiry(cfg.expiresString)
	if err != nil {
		log.Println(err.Error())
		printUsage()
		return
	}

	info, err := os.Stat(cfg.filePath)
	if err != nil {
		log.Println("error occured:", err.Error())
		return
	}

	serverFilename := info.Name()
	if len(cfg.customFilename) > 0 {
		serverFilename = cfg.customFilename
	}

	isEncrypting := len(cfg.password) > 0
	if isEncrypting {
		bar := progressbar.NewOptions(int(info.Size()),
			progressbar.OptionShowBytes(true),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetVisibility(!cfg.suppressOutput),
			progressbar.OptionSetDescription("[cyan][1/2][reset] encrypting file..."))

		err := encryptFile(cfg.filePath, encryptedFilename, cfg.password, bar)
		log.Println()
		if err != nil {
			log.Println("error occured:", err.Error())
			return
		}
		log.Println()

		if len(cfg.dryFilename) > 0 {
			log.Println("encryption complete!")
			return
		}

		log.Println("encryption complete! initializing upload...")

		info, err = os.Stat(encryptedFilename)
		if err != nil {
			log.Println("error occured:", err.Error())
			return
		}
	}

	optionStr := "[2/2]"
	if !isEncrypting {
		optionStr = "[1/1]"
	}

	bar := progressbar.NewOptions(int(info.Size()),
		progressbar.OptionShowBytes(true),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowTotalBytes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetVisibility(!cfg.suppressOutput),
		progressbar.OptionSetDescription("[cyan]"+optionStr+"[reset] uploading file..."))

	alias, err := streamFileUpload(encryptedFilename, cfg.serverUrl+"/api", info, serverFilename, isEncrypting, int(expires), bar)
	if err != nil {
		log.Println("error occured:", err.Error())
		return
	}

	log.Println()
	log.Println()
	log.Println("upload complete!")

	fileUrl, err := url.JoinPath(cfg.serverUrl, alias)
	if err != nil {
		fmt.Println("error occured:", err.Error())
		return
	}

	if cfg.copy {
		err = clipboard.WriteAll(fileUrl)
		if err != nil {
			fmt.Println("error copying to clipboard:", err.Error())
		}
		log.Println("(wrote to clipboard)")
	}

	log.Print("\033[1m")
	fmt.Printf("%s", fileUrl)
	log.Print("\033[0m")

	if isEncrypting {
		err = os.Remove(encryptedFilename)
		if err != nil {
			log.Println("error while deleting file:", err.Error())
			return
		}
	}
}

func streamFileUpload(filePath string, apiPath string, ogFileInfo os.FileInfo, serverFilename string, encrypted bool, expires int, bar *progressbar.ProgressBar) (string, error) {
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

	return string(respBody), nil
}

func encryptFile(filename string, encryptedOutput string, password string, progressBar *progressbar.ProgressBar) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	outFile, err := os.Create(encryptedOutput)
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
