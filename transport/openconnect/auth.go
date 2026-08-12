package openconnect

import (
	"context"
	"net/http"

	openconnect "github.com/sagernet/sing-openconnect"
)

type AuthFormFieldKind string

const (
	AuthFormFieldText     AuthFormFieldKind = "text"
	AuthFormFieldPassword AuthFormFieldKind = "password"
	AuthFormFieldSelect   AuthFormFieldKind = "select"
)

// AuthProvider answers one challenge for one Client. The response is applied
// only to the challenge that triggered this call.
type AuthProvider interface {
	Respond(ctx context.Context, challenge AuthChallenge) (AuthResponse, error)
}

type AuthChallenge struct {
	Banner  string
	Message string
	Error   string
	Form    *AuthForm
	Browser *BrowserRequest
}

type AuthForm struct {
	Fields []AuthFormField
}

type AuthFormField struct {
	SubmissionKey string
	Name          string
	Label         string
	Kind          AuthFormFieldKind
	Value         string
	Options       []AuthFormChoice
}

type AuthFormChoice struct {
	Value string
	Label string
}

type BrowserRequest struct {
	URL                 string
	FinalURL            string
	CallbackURLPrefixes []string
	CookieNames         []string
	EarlyCookieNames    []string
	HeaderNames         []string
}

type BrowserCookie struct {
	Name  string
	Value string
}

type BrowserResult struct {
	FinalURL string
	Cookies  []BrowserCookie
	Header   http.Header
}

type AuthResponse struct {
	FormValues map[string]string
	Browser    *BrowserResult
}

func authChallengeFromCore(challenge openconnect.AuthChallenge) AuthChallenge {
	result := AuthChallenge{Banner: challenge.Banner, Message: challenge.Message, Error: challenge.Error}
	if challenge.Form != nil {
		result.Form = &AuthForm{Fields: make([]AuthFormField, len(challenge.Form.Fields))}
		for index, field := range challenge.Form.Fields {
			mapped := AuthFormField{
				SubmissionKey: field.SubmissionKey,
				Name:          field.Name,
				Label:         field.Label,
				Kind:          AuthFormFieldKind(field.Kind),
				Value:         field.Value,
				Options:       make([]AuthFormChoice, len(field.Options)),
			}
			for optionIndex, option := range field.Options {
				mapped.Options[optionIndex] = AuthFormChoice{Value: option.Value, Label: option.Label}
			}
			result.Form.Fields[index] = mapped
		}
	}
	if challenge.Browser != nil {
		result.Browser = &BrowserRequest{
			URL:                 challenge.Browser.URL,
			FinalURL:            challenge.Browser.FinalURL,
			CallbackURLPrefixes: append([]string(nil), challenge.Browser.CallbackURLPrefixes...),
			CookieNames:         append([]string(nil), challenge.Browser.CookieNames...),
			EarlyCookieNames:    append([]string(nil), challenge.Browser.EarlyCookieNames...),
			HeaderNames:         append([]string(nil), challenge.Browser.HeaderNames...),
		}
	}
	return result
}

func authResponseToCore(response AuthResponse) openconnect.AuthResponse {
	result := openconnect.AuthResponse{}
	if response.FormValues != nil {
		result.Form = &openconnect.AuthFormResponse{Values: cloneStringMap(response.FormValues)}
	}
	if response.Browser != nil {
		cookies := make([]openconnect.BrowserCookie, len(response.Browser.Cookies))
		for index, cookie := range response.Browser.Cookies {
			cookies[index] = openconnect.BrowserCookie{Name: cookie.Name, Value: cookie.Value}
		}
		result.Browser = &openconnect.BrowserResult{
			FinalURL: response.Browser.FinalURL,
			Cookies:  cookies,
			Header:   response.Browser.Header.Clone(),
		}
	}
	return result
}

func cloneAuthChallenge(challenge AuthChallenge) AuthChallenge {
	if challenge.Form != nil {
		form := &AuthForm{Fields: make([]AuthFormField, len(challenge.Form.Fields))}
		copy(form.Fields, challenge.Form.Fields)
		for index := range form.Fields {
			form.Fields[index].Options = append([]AuthFormChoice(nil), challenge.Form.Fields[index].Options...)
		}
		challenge.Form = form
	}
	if challenge.Browser != nil {
		browser := *challenge.Browser
		browser.CallbackURLPrefixes = append([]string(nil), challenge.Browser.CallbackURLPrefixes...)
		browser.CookieNames = append([]string(nil), challenge.Browser.CookieNames...)
		browser.EarlyCookieNames = append([]string(nil), challenge.Browser.EarlyCookieNames...)
		browser.HeaderNames = append([]string(nil), challenge.Browser.HeaderNames...)
		challenge.Browser = &browser
	}
	return challenge
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func sanitizeAuthChallenge(challenge AuthChallenge, secrets []string) AuthChallenge {
	challenge = cloneAuthChallenge(challenge)
	challenge.Banner = redactErrorMessage(challenge.Banner, secrets)
	challenge.Message = redactErrorMessage(challenge.Message, secrets)
	challenge.Error = redactErrorMessage(challenge.Error, secrets)
	if challenge.Form != nil {
		for index := range challenge.Form.Fields {
			field := &challenge.Form.Fields[index]
			field.Label = redactErrorMessage(field.Label, secrets)
			if field.Kind == AuthFormFieldPassword {
				field.Value = ""
			} else {
				field.Value = redactErrorMessage(field.Value, secrets)
			}
			for optionIndex := range field.Options {
				option := &field.Options[optionIndex]
				option.Value = redactErrorMessage(option.Value, secrets)
				option.Label = redactErrorMessage(option.Label, secrets)
			}
		}
	}
	if challenge.Browser != nil {
		challenge.Browser.URL = redactErrorMessage(challenge.Browser.URL, secrets)
		challenge.Browser.FinalURL = redactErrorMessage(challenge.Browser.FinalURL, secrets)
	}
	return challenge
}

func sanitizeEventAuthChallenge(challenge AuthChallenge, secrets []string) AuthChallenge {
	challenge = cloneAuthChallenge(challenge)
	if challenge.Form != nil {
		for index := range challenge.Form.Fields {
			field := &challenge.Form.Fields[index]
			field.SubmissionKey = redactErrorMessage(field.SubmissionKey, secrets)
			field.Name = redactErrorMessage(field.Name, secrets)
		}
	}
	if challenge.Browser != nil {
		redactStrings(challenge.Browser.CallbackURLPrefixes, secrets)
		redactStrings(challenge.Browser.CookieNames, secrets)
		redactStrings(challenge.Browser.EarlyCookieNames, secrets)
		redactStrings(challenge.Browser.HeaderNames, secrets)
	}
	return challenge
}

func redactStrings(values []string, secrets []string) {
	for index := range values {
		values[index] = redactErrorMessage(values[index], secrets)
	}
}
