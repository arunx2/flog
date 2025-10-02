package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Generate generates the logs with given options
func Generate(option *Option) error {
	var (
		splitCount = 1
		created    = time.Now()

		interval time.Duration
		delay    time.Duration
	)

	if option.Sleep > 0 {
		interval = option.Sleep
	}

	logFileName := option.Output
	writer, err := NewWriter(option.Type, logFileName)
	if err != nil {
		return err
	}

	if option.Forever {
		for {
			totalWrittenBytes := 0
			writtenBytes, _ := generateByRate(option, writer)
			totalWrittenBytes += writtenBytes
			if (option.Type != "stdout") && (option.SplitBy > 0) && (totalWrittenBytes > option.SplitBy) {
				writer.Close()
				fmt.Printf("File %s is created\n", logFileName)
				splitCount++
				logFileName = NewSplitFileName(option.Output, splitCount)
				writer, err = NewWriter(option.Type, logFileName)
				if err != nil {

				}
			}
		}
	}

	if option.Number > 0 {
		// Generates the logs until the certain number of lines is reached
		for line := 0; line < option.Number; line++ {
			time.Sleep(delay)
			log := NewLog(option.Format, created, option.Bytes)
			_, _ = writer.Write([]byte(log + "\n"))

			if (option.Type != "stdout") && (option.SplitBy > 0) && (line > option.SplitBy*splitCount) {
				_ = writer.Close()
				fmt.Println(logFileName, "is created.")

				logFileName = NewSplitFileName(option.Output, splitCount)
				writer, _ = NewWriter(option.Type, logFileName)

				splitCount++
			}
			created = created.Add(interval)
		}
	}

	if option.Type != "stdout" {
		_ = writer.Close()
		fmt.Println(logFileName, "is created.")
	}
	return nil
}

func generateByRate(option *Option, writer io.WriteCloser) (int, int) {
	start := time.Now()
	generatedBytes := 0
	generatedRecords := 0
	for i := 0; i < option.Rate; i++ {
		log := NewLog(option.Format, time.Now(), option.Bytes) + "\n"
		_, _ = writer.Write([]byte(log))
		generatedBytes += len(log)
		generatedRecords++
	}
	elapsed := time.Since(start)
	time.Sleep(time.Second - elapsed)
	return generatedBytes, generatedRecords
}

// NewWriter returns a closeable writer corresponding to given log type
func NewWriter(logType string, logFileName string) (io.WriteCloser, error) {
	switch logType {
	case "stdout":
		return os.Stdout, nil
	case "log":
		logFile, err := os.Create(logFileName)
		if err != nil {
			return nil, err
		}
		return logFile, nil
	case "gz":
		logFile, err := os.Create(logFileName)
		if err != nil {
			return nil, err
		}
		return gzip.NewWriter(logFile), nil
	default:
		return nil, nil
	}
}

// NewLog creates a log for given format
func NewLog(format string, t time.Time, length int) string {
	switch format {
	case "apache_common":
		return NewApacheCommonLog(t)
	case "apache_combined":
		return NewApacheCombinedLog(t)
	case "apache_error":
		return NewApacheErrorLog(t, length)
	case "rfc3164":
		return NewRFC3164Log(t, length)
	case "rfc5424":
		return NewRFC5424Log(t, length)
	case "common_log":
		return NewCommonLogFormat(t)
	case "json":
		return NewJSONLogFormat(t)
	case "spring_boot":
		return NewSpringBootLogFormat(t, length)
	case "infoblox_dns_request":
		return NewInfobloxDNSRequestLog(t)
	case "infoblox_dns_response":
		return NewInfobloxDNSResponseLog(t)
	case "infoblox_dns":
		return NewInfobloxDNSLog(t)
	default:
		return ""
	}
}

// NewSplitFileName creates a new file path with split count
func NewSplitFileName(path string, count int) string {
	logFileNameExt := filepath.Ext(path)
	pathWithoutExt := strings.TrimSuffix(path, logFileNameExt)
	return pathWithoutExt + strconv.Itoa(count) + logFileNameExt
}
