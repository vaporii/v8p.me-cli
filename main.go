package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	fmt.Println("hello, world")
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
	case "s", "sec", "secs", "second", "seconds":
		multiplier = 1
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
