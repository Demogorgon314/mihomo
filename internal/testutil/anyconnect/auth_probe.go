package anyconnect

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

// AuthProbeOptions configures the independent AnyConnect XMLPOST probe.
type AuthProbeOptions struct {
	Address           string
	ServerName        string
	RootCAs           *x509.CertPool
	Username          string
	Password          string
	ChallengeResponse string
}

type authProbeDocument struct {
	SessionToken string `xml:"session-token"`
	Auth         struct {
		Complete *struct{} `xml:"authentication-complete"`
		Form     *struct {
			Method string `xml:"method,attr"`
			Action string `xml:"action,attr"`
			Inputs []struct {
				Type string `xml:"type,attr"`
				Name string `xml:"name,attr"`
			} `xml:"input"`
		} `xml:"form"`
	} `xml:"auth"`
}

// RunAuthProbe completes primary credentials and an optional second challenge,
// returning the issued webvpn cookie without using the production client.
func RunAuthProbe(ctx context.Context, options AuthProbeOptions) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("authentication probe context is required")
	}
	if options.Address == "" || options.ServerName == "" || options.RootCAs == nil || options.Username == "" || options.Password == "" {
		return "", fmt.Errorf("authentication probe address, server name, roots, username, and password are required")
	}
	_, port, err := net.SplitHostPort(options.Address)
	if err != nil {
		return "", fmt.Errorf("parse authentication probe address: %w", err)
	}
	serverURL, err := url.Parse("https://" + net.JoinHostPort(options.ServerName, port) + "/")
	if err != nil {
		return "", fmt.Errorf("build authentication probe URL: %w", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", fmt.Errorf("create authentication probe cookie jar: %w", err)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: options.ServerName,
			RootCAs:    options.RootCAs,
		},
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, options.Address)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Jar: jar}
	document, finalURL, err := postAuthProbe(ctx, client, serverURL, []byte(`<?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="init"/>`))
	if err != nil {
		return "", err
	}
	for round := 0; round < 2; round++ {
		if document.Auth.Complete != nil {
			return authProbeCookie(jar, finalURL, document.SessionToken)
		}
		if document.Auth.Form == nil || !strings.EqualFold(document.Auth.Form.Method, http.MethodPost) || document.Auth.Form.Action == "" {
			return "", fmt.Errorf("authentication probe response omitted a POST form")
		}
		values := make(map[string]string, len(document.Auth.Form.Inputs))
		for _, field := range document.Auth.Form.Inputs {
			switch field.Name {
			case "username":
				values[field.Name] = options.Username
			case "password":
				values[field.Name] = options.Password
			case "answer":
				values[field.Name] = options.ChallengeResponse
			default:
				return "", fmt.Errorf("authentication probe received unsupported field %q", field.Name)
			}
		}
		targetURL, err := finalURL.Parse(document.Auth.Form.Action)
		if err != nil {
			return "", fmt.Errorf("resolve authentication probe form action: %w", err)
		}
		body := buildAuthProbeReply(values)
		document, finalURL, err = postAuthProbe(ctx, client, targetURL, body)
		if err != nil {
			return "", err
		}
	}
	if document.Auth.Complete == nil {
		return "", fmt.Errorf("authentication probe exceeded form round limit")
	}
	return authProbeCookie(jar, finalURL, document.SessionToken)
}

func postAuthProbe(ctx context.Context, client *http.Client, targetURL *url.URL, body []byte) (authProbeDocument, *url.URL, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL.String(), bytes.NewReader(body))
	if err != nil {
		return authProbeDocument{}, nil, fmt.Errorf("create authentication probe request: %w", err)
	}
	request.Header.Set("Content-Type", "application/xml; charset=utf-8")
	response, err := client.Do(request)
	if err != nil {
		return authProbeDocument{}, nil, fmt.Errorf("send authentication probe request: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maximumFakeAuthBodySize+1))
	if err != nil {
		return authProbeDocument{}, nil, fmt.Errorf("read authentication probe response: %w", err)
	}
	if len(responseBody) > maximumFakeAuthBodySize {
		return authProbeDocument{}, nil, fmt.Errorf("authentication probe response exceeds %d bytes", maximumFakeAuthBodySize)
	}
	if response.StatusCode != http.StatusOK {
		return authProbeDocument{}, nil, fmt.Errorf("authentication probe rejected with HTTP %d", response.StatusCode)
	}
	var document authProbeDocument
	if err := xml.Unmarshal(responseBody, &document); err != nil {
		return authProbeDocument{}, nil, fmt.Errorf("parse authentication probe response: %w", err)
	}
	return document, response.Request.URL, nil
}

func buildAuthProbeReply(values map[string]string) []byte {
	var body strings.Builder
	body.WriteString(`<?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="auth-reply"><auth>`)
	for _, name := range []string{"username", "password", "answer"} {
		value, exists := values[name]
		if !exists {
			continue
		}
		wireName := name
		if name == "answer" {
			wireName = "password"
		}
		body.WriteByte('<')
		body.WriteString(wireName)
		body.WriteByte('>')
		body.WriteString(xmlEscape(value))
		body.WriteString("</")
		body.WriteString(wireName)
		body.WriteByte('>')
	}
	body.WriteString(`</auth></config-auth>`)
	return []byte(body.String())
}

func authProbeCookie(jar http.CookieJar, serverURL *url.URL, sessionToken string) (string, error) {
	for _, cookie := range jar.Cookies(serverURL) {
		if cookie.Name == "webvpn" && cookie.Value != "" {
			if sessionToken != "" && cookie.Value != sessionToken {
				return "", fmt.Errorf("authentication cookie and session token differ")
			}
			return cookie.Value, nil
		}
	}
	return "", fmt.Errorf("authentication probe completed without a webvpn cookie")
}
