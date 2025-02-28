package main

import (
	"flag"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var password string
var copy bool
var expires string
var filename string

func main() {
	const passwordUsage = "enable encryption and set a password (-p <password>)"
	flag.StringVar(&password, "password", "", passwordUsage)
	flag.StringVar(&password, "p", "", passwordUsage)

	const copyUsage = "copy the resulting url to the clipboard (-c)"
	flag.BoolVar(&copy, "copy", false, copyUsage)
	flag.BoolVar(&copy, "c", false, copyUsage)

	const expiresUsage = "set the expiry date after which the file should be deleted (-e 1d), (-e 3 weeks), (-e 5 m)"
	flag.StringVar(&expires, "expires", "1w", expiresUsage)
	flag.StringVar(&expires, "e", "1w", expiresUsage)

	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("error: no filename provided.")
		printUsage()
		return
	}

	filename = args[len(args)-1]
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
