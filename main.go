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
)

var password string
var copy bool
var expiresString string
var expires int64
var filename string
var serverUrl string

const (
	iterations = 100000
	chunkSize  = 1 * 1000 * 1000 // 1mb per chunk
	saltSize   = 16
	nonceSize  = 12
)

func main() {
	const passwordUsage = "enable encryption and set a password (-p <password>)"
	flag.StringVar(&password, "password", "", passwordUsage)
	flag.StringVar(&password, "p", "", passwordUsage)

	const copyUsage = "copy the resulting url to the clipboard (-c)"
	flag.BoolVar(&copy, "copy", false, copyUsage)
	flag.BoolVar(&copy, "c", false, copyUsage)

	const expiresUsage = "set the expiry date after which the file should be deleted (-e 1d), (-e 3 weeks), (-e 5 m)"
	flag.StringVar(&expiresString, "expires", "0m", expiresUsage)
	flag.StringVar(&expiresString, "e", "0m", expiresUsage)

	const serverUsage = "directs requests to a custom server instead of default of https://v8p.me (-s <url>)"
	flag.StringVar(&serverUrl, "server", "https://v8p.me", serverUsage)
	flag.StringVar(&serverUrl, "s", "https://v8p.me", serverUsage)

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

	_ = expires

	filename = args[len(args)-1]

	if len(password) > 0 {
		err := encryptFile(filename, password)
		if err != nil {
			fmt.Println("error occured:", err.Error())
			return
		}

		info, err := os.Stat(filename)
		if err != nil {
			fmt.Println("error occured:", err.Error())
			return
		}

		err = streamFileUpload("v8p.me-cli.tmp", serverUrl+"/api", info, len(password) > 0, int(expires))
		if err != nil {
			fmt.Println("error occured:", err.Error())
			return
		}
	}
}

func streamFileUpload(filePath, apiPath string, ogFileInfo os.FileInfo, encrypted bool, expires int) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", apiPath, file)
	if err != nil {
		return err
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
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return errors.New("unexpected error: " + resp.Status)
	}

	fmt.Println(serverUrl + "/" + string(respBody))
	return nil
}

func encryptFile(filename string, password string) error {
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
	fmt.Println("v8p [arguments] <filename>")
	fmt.Println()
	fmt.Println("arguments:")
	fmt.Println("--password, -p <password>    enable encryption and set password")
	fmt.Println("--expires,  -e <date str>    set expiry date of file (-e 1d), (-e 3 weeks), (--expires 5 m)")
	fmt.Println("--copy,     -c               if present, automatically copy returned URL to clipboard")
	fmt.Println("--server,   -s <url>         direct requests to custom server instead of default (https://v8p.me) (-s https://example.com)")
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
