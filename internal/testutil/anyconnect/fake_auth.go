package anyconnect

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const maximumFakeAuthBodySize = 64 * 1024

type fakeAuthRequest struct {
	Type string `xml:"type,attr"`
	Auth struct {
		Username string `xml:"username"`
		Password string `xml:"password"`
	} `xml:"auth"`
}

func (g *Gateway) handleAuthRequest(connection net.Conn, request *http.Request) error {
	if !g.scenario.Authentication.Enabled {
		return writeHTTPRejection(connection, http.StatusNotFound)
	}
	if request.Method != http.MethodPost {
		return writeHTTPRejection(connection, http.StatusMethodNotAllowed)
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumFakeAuthBodySize+1))
	if err != nil {
		return fmt.Errorf("read fake authentication request: %w", err)
	}
	if len(body) > maximumFakeAuthBodySize {
		return writeHTTPRejection(connection, http.StatusRequestEntityTooLarge)
	}
	var document fakeAuthRequest
	if err := xml.Unmarshal(body, &document); err != nil {
		return writeHTTPRejection(connection, http.StatusBadRequest)
	}
	switch document.Type {
	case "init":
		g.authLock.Lock()
		g.authChallengePending = false
		g.authLock.Unlock()
		g.record("auth-form", "issued primary credential form")
		return writeFakeAuthXML(connection, http.StatusOK, fakePrimaryAuthForm, "")
	case "auth-reply":
		return g.handleAuthReply(connection, document)
	default:
		return writeHTTPRejection(connection, http.StatusBadRequest)
	}
}

func (g *Gateway) handleAuthReply(connection net.Conn, document fakeAuthRequest) error {
	authentication := g.scenario.Authentication
	g.authLock.Lock()
	defer g.authLock.Unlock()
	if g.authChallengePending {
		if document.Auth.Password != authentication.ChallengeResponse {
			g.record("auth-reject", "rejected challenge response")
			return writeHTTPRejection(connection, http.StatusUnauthorized)
		}
		g.authChallengePending = false
		return g.completeAuthentication(connection)
	}
	if document.Auth.Username != authentication.Username || document.Auth.Password != authentication.Password {
		g.record("auth-reject", "rejected primary credentials")
		return writeHTTPRejection(connection, http.StatusUnauthorized)
	}
	if authentication.Challenge != "" {
		g.authChallengePending = true
		form := strings.ReplaceAll(fakeChallengeAuthForm, "{{CHALLENGE}}", xmlEscape(authentication.Challenge))
		g.record("auth-form", "issued secondary challenge form")
		return writeFakeAuthXML(connection, http.StatusOK, form, "")
	}
	return g.completeAuthentication(connection)
}

func (g *Gateway) completeAuthentication(connection net.Conn) error {
	g.authGeneration++
	g.activeCookie = g.scenario.Cookie + "-" + strconv.FormatUint(g.authGeneration, 10)
	g.activeCookieUses = 0
	response := strings.ReplaceAll(fakeAuthComplete, "{{TOKEN}}", xmlEscape(g.activeCookie))
	g.record("auth-complete", "issued tunnel cookie")
	return writeFakeAuthXML(connection, http.StatusOK, response, g.activeCookie)
}

func (g *Gateway) consumeTunnelCookie(value string) bool {
	if !g.scenario.Authentication.Enabled {
		return value == g.scenario.Cookie
	}
	g.authLock.Lock()
	defer g.authLock.Unlock()
	if value == "" || value != g.activeCookie {
		return false
	}
	maximumUses := g.scenario.Authentication.CookieUses
	if maximumUses > 0 && g.activeCookieUses >= maximumUses {
		return false
	}
	g.activeCookieUses++
	return true
}

func writeFakeAuthXML(connection net.Conn, status int, document string, cookie string) error {
	statusText := http.StatusText(status)
	if statusText == "" {
		return errors.New("invalid fake authentication HTTP status")
	}
	body := []byte(document)
	var response strings.Builder
	response.WriteString("HTTP/1.1 ")
	response.WriteString(strconv.Itoa(status))
	response.WriteByte(' ')
	response.WriteString(statusText)
	response.WriteString("\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: ")
	response.WriteString(strconv.Itoa(len(body)))
	response.WriteString("\r\nConnection: close\r\n")
	if cookie != "" {
		response.WriteString("Set-Cookie: webvpn=")
		response.WriteString(cookie)
		response.WriteString("; Path=/; Secure; HttpOnly\r\n")
	}
	response.WriteString("\r\n")
	if err := writeFull(connection, []byte(response.String())); err != nil {
		return fmt.Errorf("write fake authentication response headers: %w", err)
	}
	if err := writeFull(connection, body); err != nil {
		return fmt.Errorf("write fake authentication response body: %w", err)
	}
	return nil
}

func xmlEscape(value string) string {
	var escaped strings.Builder
	_ = xml.EscapeText(&escaped, []byte(value))
	return escaped.String()
}

const fakePrimaryAuthForm = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth><auth id="main"><banner>Phase 0 fake gateway</banner><form method="POST" action="/auth"><input type="text" name="username" label="Username"/><input type="password" name="password" label="Password"/></form></auth></config-auth>`

const fakeChallengeAuthForm = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth><auth id="challenge"><message>{{CHALLENGE}}</message><form method="POST" action="/auth"><input type="password" name="answer" label="Response"/></form></auth></config-auth>`

const fakeAuthComplete = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth><session-token>{{TOKEN}}</session-token><auth id="success"><authentication-complete/></auth></config-auth>`
