package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v6"
)

const (
	// ApacheCommonLog : {host} {user-identifier} {auth-user-id} [{datetime}] "{method} {request} {protocol}" {response-code} {bytes}
	ApacheCommonLog = "%s - %s [%s] \"%s %s %s\" %d %d"
	// ApacheCombinedLog : {host} {user-identifier} {auth-user-id} [{datetime}] "{method} {request} {protocol}" {response-code} {bytes} "{referrer}" "{agent}"
	ApacheCombinedLog = "%s - %s [%s] \"%s %s %s\" %d %d \"%s\" \"%s\""
	// ApacheErrorLog : [{timestamp}] [{module}:{severity}] [pid {pid}:tid {thread-id}] [client %{client}:{port}] %{message}
	ApacheErrorLog = "[%s] [%s:%s] [pid %d:tid %d] [client %s:%d] %s"
	// RFC3164Log : <priority>{timestamp} {hostname} {application}[{pid}]: {message}
	RFC3164Log = "<%d>%s %s %s[%d]: %s"
	// RFC5424Log : <priority>{version} {iso-timestamp} {hostname} {application} {pid} {message-id} {structured-data} {message}
	RFC5424Log = "<%d>%d %s %s %s %d ID%d %s %s"
	// CommonLogFormat : {host} {user-identifier} {auth-user-id} [{datetime}] "{method} {request} {protocol}" {response-code} {bytes}
	CommonLogFormat = "%s - %s [%s] \"%s %s %s\" %d %d"
	// JSONLogFormat : {"host": "{host}", "user-identifier": "{user-identifier}", "datetime": "{datetime}", "method": "{method}", "request": "{request}", "protocol": "{protocol}", "status", {status}, "bytes": {bytes}, "referer": "{referer}"}
	JSONLogFormat = `{"host":"%s", "user-identifier":"%s", "datetime":"%s", "method": "%s", "request": "%s", "protocol":"%s", "status":%d, "bytes":%d, "referer": "%s"}`
	// SpringBootLogFormat : "{timestamp} {severity} {pid} --- [{thread-id}] {classname}: {message}"
	SpringBootLogFormat = "%s %s %s --- [%s] %s: %s"
	// InfobloxDNSRequestLogFormat : "{timestamp} client [@iface] {ip#port}: query: {domain}. {class} {type} {setDC} ({nsip})"
	InfobloxDNSRequestLogFormat = "%s client%s%s#%d: query: %s. %s %s %s (%s)"
	// InfoblocDNSResponseLogFormat : {timestamp} client {ip}#{port}: [view:] {proto}: query: {domain}. {class} {type} response: {rcode} {flags} {rr}
	InfobloxDNSResponseLogFormat = "%s client %s#%d: %s%s: query: %s. %s %s response: %s %s %s"
)

func message(length int) string {
	if length < 1 {
		return ""
	}

	msg := gofakeit.Word()
	for len(msg) <= length {
		msg = msg + " " + gofakeit.Word()
	}
	return msg[:length-1]
}

// NewApacheCommonLog creates a log string with apache common log format
func NewApacheCommonLog(t time.Time) string {
	return fmt.Sprintf(
		ApacheCommonLog,
		gofakeit.IPv4Address(),
		RandAuthUserID(),
		t.Format(Apache),
		gofakeit.HTTPMethod(),
		RandResourceURI(),
		RandHTTPVersion(),
		gofakeit.HTTPStatusCode(),
		gofakeit.Number(0, 30000),
	)
}

// NewApacheCombinedLog creates a log string with apache combined log format
func NewApacheCombinedLog(t time.Time) string {
	return fmt.Sprintf(
		ApacheCombinedLog,
		gofakeit.IPv4Address(),
		RandAuthUserID(),
		t.Format(Apache),
		gofakeit.HTTPMethod(),
		RandResourceURI(),
		RandHTTPVersion(),
		gofakeit.HTTPStatusCode(),
		gofakeit.Number(30, 100000),
		gofakeit.URL(),
		gofakeit.UserAgent(),
	)
}

// NewApacheErrorLog creates a log string with apache error log format
func NewApacheErrorLog(t time.Time, length int) string {
	preMsg := fmt.Sprintf(
		ApacheErrorLog,
		t.Format(ApacheError),
		gofakeit.Word(),
		gofakeit.LogLevel("apache"),
		gofakeit.Number(1, 10000),
		gofakeit.Number(1, 10000),
		gofakeit.IPv4Address(),
		gofakeit.Number(1, 65535),
		gofakeit.HackerPhrase(),
	)
	return preMsg + message(length-len(preMsg))
}

// NewRFC3164Log creates a log string with syslog (RFC3164) format
func NewRFC3164Log(t time.Time, length int) string {
	preMsg := fmt.Sprintf(
		RFC3164Log,
		gofakeit.Number(0, 191),
		t.Format(RFC3164),
		strings.ToLower(gofakeit.Username()),
		gofakeit.Word(),
		gofakeit.Number(1, 10000),
		gofakeit.HackerPhrase(),
	)
	return preMsg + message(length-len(preMsg))
}

// NewRFC5424Log creates a log string with syslog (RFC5424) format
func NewRFC5424Log(t time.Time, length int) string {
	preMsg := fmt.Sprintf(
		RFC5424Log,
		gofakeit.Number(0, 191),
		gofakeit.Number(1, 3),
		t.Format(RFC5424),
		gofakeit.DomainName(),
		gofakeit.Word(),
		gofakeit.Number(1, 10000),
		gofakeit.Number(1, 1000),
		"-", // TODO: structured data
		gofakeit.HackerPhrase(),
	)
	return preMsg + message(length-len(preMsg))
}

// NewCommonLogFormat creates a log string with common log format
func NewCommonLogFormat(t time.Time) string {
	return fmt.Sprintf(
		CommonLogFormat,
		gofakeit.IPv4Address(),
		RandAuthUserID(),
		t.Format(CommonLog),
		gofakeit.HTTPMethod(),
		RandResourceURI(),
		RandHTTPVersion(),
		gofakeit.HTTPStatusCode(),
		gofakeit.Number(0, 30000),
	)
}

// NewJSONLogFormat creates a log string with json log format
func NewJSONLogFormat(t time.Time) string {
	return fmt.Sprintf(
		JSONLogFormat,
		gofakeit.IPv4Address(),
		RandAuthUserID(),
		t.Format(CommonLog),
		gofakeit.HTTPMethod(),
		RandResourceURI(),
		RandHTTPVersion(),
		gofakeit.HTTPStatusCode(),
		gofakeit.Number(0, 30000),
		gofakeit.URL(),
	)
}

// NewSpringBootLogFormat creates a log string with spring boot default format
func NewSpringBootLogFormat(t time.Time, length int) string {
	preMsg := fmt.Sprintf(
		SpringBootLogFormat,
		t.Format(Java),
		strings.ToUpper(gofakeit.LogLevel("general")),
		gofakeit.StreetNumber(),
		gofakeit.BuzzWord(),
		gofakeit.DomainSuffix()+"."+gofakeit.BS()+"."+gofakeit.Word()+"."+gofakeit.FirstName(),
		gofakeit.HackerPhrase(),
	)
	return preMsg + message(length-len(preMsg))
}

// NewInfobloxDNSRequestLog creates a log string with infoblox dns request log format (not verified. Built based on user info)
func NewInfobloxDNSRequestLog(t time.Time) string {
	at := " "
	if gofakeit.Bool() {
		at += "@" + gofakeit.Word() + " "
	}
	return fmt.Sprintf(
		InfobloxDNSRequestLogFormat,
		t.Format(InfobloxDNS),
		at,
		gofakeit.IPv4Address(),
		gofakeit.Number(30000, 65535),
		gofakeit.DomainName(),
		"IN",
		"A",
		"+EDC",
		gofakeit.IPv4Address(),
	)
}

// NewInfobloxDNSResponseLog creates a log string with infoblox dns response log format (not verified. Built based on user info)
func NewInfobloxDNSResponseLog(t time.Time) string {
	view := ""
	protocol := "tcp"
	if gofakeit.Bool() {
		view = "default: "
	}
	if gofakeit.Bool() {
		protocol = "udp"
	}
	return fmt.Sprintf(
		InfobloxDNSResponseLogFormat,
		t.Format(InfobloxDNS),
		gofakeit.IPv4Address(),
		gofakeit.Number(30000, 65535),
		view,
		protocol,
		gofakeit.DomainName(),
		"IN",
		"A",
		"NOERROR",
		"qr aa",
		gofakeit.IPv4Address(),
	)
}

// NewInfobloxDNSLog creates either a request or response log
func NewInfobloxDNSLog(t time.Time) string {
	if gofakeit.Bool() {
		return NewInfobloxDNSRequestLog(t)
	}
	return NewInfobloxDNSResponseLog(t)
}
