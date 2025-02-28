package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var password string
var copy bool
var expiresString string
var expires int64
var filename string

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
	flag.StringVar(&expiresString, "expires", "1w", expiresUsage)
	flag.StringVar(&expiresString, "e", "1w", expiresUsage)

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
	}
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
	fmt.Println("--password, -p <password>    enables encryption and uses password")
	fmt.Println("--expires,  -e <date str>    sets the expiry date of the file (-e 1d), (-e 3 weeks), (--expires 5 m)")
	fmt.Println("--copy,     -c               if present, automatically copies the returned URL to the clipboard")
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
