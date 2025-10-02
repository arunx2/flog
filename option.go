package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

const version = "0.6.8"
const usage = `flog is a fake log generator for common log formats

Usage: flog [options]

Version: %s

Options:
  -f, --format string      log format. available formats:
                           - apache_common
                           - apache_combined
                           - apache_error (default)
                           - rfc3164
                           - rfc5424
                           - json
                           - spring_boot
                           - infoblox_dns_request
                           - infoblox_dns_response
                           - infoblox_dns
  -o, --output string      output filename. Path-like is allowed. (default "generated.log")
  -t, --type string        log output type. available types:
                           - stdout (default)
                           - log
                           - gz
  -n, --number integer     number of lines to generate.
  -b, --bytes integer      size of log line to generate in bytes (default 512).
  -s, --sleep duration     fix creation time interval for each log (default unit "seconds"). It does not actually sleep.
                           examples: 10, 20ms, 5s, 1m
  -r, --rate rate          # of logs per second

  -p, --split-by integer   set the maximum number of lines or maximum size in bytes of a log file.
                           with "number" option, the logs will be split whenever the maximum number of lines is reached.
                           with "byte" option, the logs will be split whenever the maximum size in bytes is reached.
  -w, --overwrite          overwrite the existing log files.
  -l, --loop               loop output forever until killed.
`

var validFormats = []string{"apache_common", "apache_combined", "apache_error", "rfc3164", "rfc5424", "common_log", "json", "spring_boot", "infoblox_dns_request", "infoblox_dns_response", "infoblox_dns"}
var validTypes = []string{"stdout", "log", "gz"}

// Option defines log generator options
type Option struct {
	Format    string
	Output    string
	Type      string
	Number    int
	Bytes     int
	Sleep     time.Duration
	Rate      int
	SplitBy   int
	Overwrite bool
	Forever   bool
}

func init() {
	pflag.Usage = printUsage
}

func printUsage() {
	fmt.Printf(usage, version)
}

func printVersion() {
	fmt.Printf("flog version %s\n", version)
}

func errorExit(err error) {
	os.Stderr.WriteString(err.Error() + "\n")
	os.Exit(-1)
}

func defaultOptions() *Option {
	return &Option{
		Format:    "apache_error",
		Output:    "generated.log",
		Type:      "stdout",
		Number:    1000,
		Bytes:     512,
		Sleep:     0.0,
		Rate:      100,
		SplitBy:   0,
		Overwrite: false,
		Forever:   false,
	}
}

// ParseFormat validates the given format
func ParseFormat(format string) (string, error) {
	if !containString(validFormats, format) {
		return "", fmt.Errorf("%s is not a valid format", format)
	}
	return format, nil
}

// ParseType validates the given type
func ParseType(logType string) (string, error) {
	if !containString(validTypes, logType) {
		return "", fmt.Errorf("%s is not a valid log type", logType)
	}
	return logType, nil
}

// ParseNumber validates the given number
func ParseNumber(lines int) (int, error) {
	if lines < 0 {
		return 0, errors.New("lines can not be negative")
	}
	return lines, nil
}

func ParseRate(rate int) (int, error) {
	if rate < 0 {
		return 0, errors.New("rate cannot be negative")
	}
	return rate, nil
}

// ParseBytes validates the given bytes
func ParseBytes(bytes int) (int, error) {
	if bytes < 0 {
		return 0, errors.New("bytes can not be negative")
	}
	return bytes, nil
}

// ParseSleep validates the given sleep
func ParseSleep(sleepString string) (time.Duration, error) {
	if strings.ContainsAny(sleepString, "nsuµmh") {
		return time.ParseDuration(sleepString)
	}
	sleep, err := strconv.ParseFloat(sleepString, 64)
	if err != nil {
		return 0, err
	}
	if sleep < 0 {
		return 0.0, errors.New("sleep time must be positive")
	}
	return time.Duration(sleep * float64(time.Second)), nil
}

// ParseSplitBy validates the given split-by
func ParseSplitBy(splitBy int) (int, error) {
	if splitBy < 0 {
		return 0, errors.New("split-by can not be negative")
	}
	return splitBy, nil
}

// ParseOptions parses given parameters from command line
func ParseOptions() *Option {
	var err error

	opts := defaultOptions()

	help := pflag.BoolP("help", "h", false, "Show this help message")
	version := pflag.BoolP("version", "v", false, "Show version")
	format := pflag.StringP("format", "f", opts.Format, "Log format")
	output := pflag.StringP("output", "o", opts.Output, "Path-like output filename")
	logType := pflag.StringP("type", "t", opts.Type, "Log output type")
	number := pflag.IntP("number", "n", opts.Number, "Number of lines to generate")
	bytes := pflag.IntP("bytes", "b", opts.Bytes, "Size of log records to generate in bytes (default 512)")
	sleepString := pflag.StringP("sleep", "s", "0s", "Creation time interval (default unit: seconds)")
	rate := pflag.IntP("rate", "r", opts.Rate, "Logs per second")
	splitBy := pflag.IntP("split", "p", opts.SplitBy, "Maximum number of lines or size of a log file")
	overwrite := pflag.BoolP("overwrite", "w", false, "Overwrite the existing log files")
	forever := pflag.BoolP("loop", "l", false, "Loop output forever until killed")

	pflag.Parse()

	if *help {
		printUsage()
		os.Exit(0)
	}
	if *version {
		printVersion()
		os.Exit(0)
	}
	if opts.Format, err = ParseFormat(*format); err != nil {
		errorExit(err)
	}
	if opts.Type, err = ParseType(*logType); err != nil {
		errorExit(err)
	}
	if opts.Number, err = ParseNumber(*number); err != nil {
		errorExit(err)
	}
	if opts.Bytes, err = ParseBytes(*bytes); err != nil {
		errorExit(err)
	}
	if opts.Sleep, err = ParseSleep(*sleepString); err != nil {
		errorExit(err)
	}
	if opts.Rate, err = ParseRate(*rate); err != nil {
		errorExit(err)
	}
	if opts.SplitBy, err = ParseSplitBy(*splitBy); err != nil {
		errorExit(err)
	}
	opts.Output = *output
	opts.Overwrite = *overwrite
	opts.Forever = *forever
	return opts
}
