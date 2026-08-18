package openconnect

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

const maximumFakeAuthBodySize = 64 * 1024

type fakeAuthRequest struct {
	Type        string `xml:"type,attr"`
	GroupSelect string `xml:"group-select"`
	Auth        struct {
		Username string `xml:"username"`
		Password string `xml:"password"`
	} `xml:"auth"`
}

func (g *AnyConnectGateway) handleAuthRequest(connection net.Conn, request *http.Request) error {
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
		if authentication := g.scenario.Authentication; authentication.HostScan {
			g.record("host-scan", "issued host scan request")
			return writeFakeAuthXML(connection, http.StatusOK, fakeHostScanAuthForm, "")
		} else if authentication.Browser {
			g.record("browser-auth", "issued browser authentication request")
			return writeFakeAuthXML(connection, http.StatusOK, fakeBrowserAuthForm, "")
		} else if authentication.AuthGroup != "" && document.GroupSelect != "" && document.GroupSelect != authentication.AuthGroup {
			g.record("auth-reject", "rejected authentication group")
			return writeHTTPRejection(connection, http.StatusUnauthorized)
		}
		g.record("auth-form", "issued primary credential form")
		return writeFakeAuthXML(connection, http.StatusOK, fakePrimaryAuthenticationForm(g.scenario.Authentication.AuthGroup, document.GroupSelect), "")
	case "auth-reply":
		return g.handleAuthReply(connection, document)
	default:
		return writeHTTPRejection(connection, http.StatusBadRequest)
	}
}

func (g *AnyConnectGateway) handleAuthReply(connection net.Conn, document fakeAuthRequest) error {
	authentication := g.scenario.Authentication
	g.authLock.Lock()
	defer g.authLock.Unlock()
	if g.authChallengePending {
		if !authentication.acceptsChallengeResponse(document.Auth.Password) {
			g.record("auth-reject", "rejected challenge response")
			return writeHTTPRejection(connection, http.StatusUnauthorized)
		}
		g.authChallengePending = false
		return g.completeAuthentication(connection)
	}
	if document.Auth.Username != authentication.Username || document.Auth.Password != authentication.Password ||
		authentication.AuthGroup != "" && document.GroupSelect != authentication.AuthGroup {
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

func (a AnyConnectAuthenticationScenario) acceptsChallengeResponse(value string) bool {
	return value != "" && slices.Contains(a.ChallengeResponses, value)
}

func (g *AnyConnectGateway) completeAuthentication(connection net.Conn) error {
	g.authGeneration++
	g.activeCookie = g.scenario.Cookie + "-" + strconv.FormatUint(g.authGeneration, 10)
	g.activeCookieUses = 0
	response := strings.ReplaceAll(fakeAuthComplete, "{{TOKEN}}", xmlEscape(g.activeCookie))
	g.record("auth-complete", "issued tunnel cookie")
	return writeFakeAuthXML(connection, http.StatusOK, response, g.activeCookie)
}

func (g *AnyConnectGateway) consumeTunnelCookie(value string) bool {
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
<config-auth><auth id="main"><banner>AnyConnect fake gateway</banner><form method="POST" action="/auth"><input type="text" name="username" label="Username"/><input type="password" name="password" label="Password"/></form></auth></config-auth>`

func fakePrimaryAuthenticationForm(authGroup string, selectedGroup string) string {
	if authGroup == "" {
		return fakePrimaryAuthForm
	}
	selected := ""
	if selectedGroup == authGroup {
		selected = ` selected="true"`
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<config-auth><auth id="main"><banner>Phase 2 fake gateway</banner><form method="POST" action="/auth"><select name="group_list" label="Group"><option value="other">Other</option><option value="` + xmlEscape(authGroup) + `"` + selected + `>` + xmlEscape(authGroup) + `</option></select><input type="text" name="username" label="Username"/><input type="password" name="password" label="Password"/></form></auth></config-auth>`
}

const fakeChallengeAuthForm = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth><auth id="challenge"><message>{{CHALLENGE}}</message><form method="POST" action="/auth"><input type="password" name="answer" label="Response"/></form></auth></config-auth>`

const fakeAuthComplete = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth><session-token>{{TOKEN}}</session-token><auth id="success"><authentication-complete/></auth></config-auth>`

const fakeBrowserAuthForm = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth><auth id="sso"><banner>Browser sign-in required</banner><sso-v2-login>https://browser.invalid/login</sso-v2-login><sso-v2-login-final>https://browser.invalid/complete</sso-v2-login-final><sso-v2-token-cookie-name>webvpn</sso-v2-token-cookie-name><form method="POST" action="/auth"><input type="sso" name="sso-token"/></form></auth></config-auth>`

const fakeHostScanAuthForm = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth><host-scan><host-scan-ticket>ticket-secret</host-scan-ticket><host-scan-token>token-secret</host-scan-token><host-scan-base-uri>/+CSCOE+/sdesktop</host-scan-base-uri><host-scan-wait-uri>/+CSCOE+/sdesktop/wait.html</host-scan-wait-uri></host-scan><auth id="main"><form method="POST" action="/auth"><input type="text" name="username" label="Username"/></form></auth></config-auth>`
