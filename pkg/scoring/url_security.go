package scoring

import (
	"fmt"
	"net"
	"net/url"

	"github.com/capiscio/capiscio-core/pkg/report"
)

// URLValidator validates URLs for security and compliance.
type URLValidator struct {
	AllowPrivateIPs bool
}

// NewURLValidator creates a new URLValidator.
func NewURLValidator(allowPrivateIPs bool) *URLValidator {
	return &URLValidator{
		AllowPrivateIPs: allowPrivateIPs,
	}
}

// Validate checks if a URL is valid and secure.
func (v *URLValidator) Validate(rawURL string, fieldName string) []report.ValidationIssue {
	var issues []report.ValidationIssue

	if rawURL == "" {
		return issues
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		issues = append(issues, report.ValidationIssue{
			Code:     "INVALID_URL_FORMAT",
			Message:  fmt.Sprintf("Invalid URL format: %v", err),
			Severity: "error",
			Field:    fieldName,
		})
		return issues
	}

	// Check scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" && parsedURL.Scheme != "grpc" {
		issues = append(issues, report.ValidationIssue{
			Code:     "INVALID_URL_SCHEME",
			Message:  "URL must use http, https, or grpc scheme",
			Severity: "error",
			Field:    fieldName,
		})
	}

	// Check host
	hostname := parsedURL.Hostname()
	if hostname == "" {
		issues = append(issues, report.ValidationIssue{
			Code:     "INVALID_URL_HOST",
			Message:  "URL must have a hostname",
			Severity: "error",
			Field:    fieldName,
		})
		return issues
	}

	// Security checks (unless allowed)
	if !v.AllowPrivateIPs {
		if isPrivateIP(hostname) {
			issues = append(issues, report.ValidationIssue{
				Code:     "INSECURE_URL_PRIVATE_IP",
				Message:  "URL resolves to a private IP address (security risk)",
				Severity: "warning", // Warning by default, Error in strict mode (handled by engine)
				Field:    fieldName,
			})
		}
		if hostname == "localhost" {
			issues = append(issues, report.ValidationIssue{
				Code:     "INSECURE_URL_LOCALHOST",
				Message:  "URL uses localhost (not accessible externally)",
				Severity: "warning",
				Field:    fieldName,
			})
		}
	}

	return issues
}

func isPrivateIP(hostname string) bool {
	ip := net.ParseIP(hostname)
	if ip == nil {
		// It's a domain name, not an IP
		return false
	}

	// Check if it's a private IP range
	// 10.0.0.0/8
	// 172.16.0.0/12
	// 192.168.0.0/16
	// 127.0.0.0/8 (Loopback)
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	return false
}
