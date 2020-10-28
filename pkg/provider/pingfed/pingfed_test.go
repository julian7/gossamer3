package pingfed

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	"github.com/GESkunkworks/gossamer3/pkg/cfg"
	"github.com/GESkunkworks/gossamer3/pkg/provider"

	"github.com/GESkunkworks/gossamer3/mocks"
	"github.com/GESkunkworks/gossamer3/pkg/creds"
	"github.com/GESkunkworks/gossamer3/pkg/prompter"
	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
)

func TestMakeAbsoluteURL(t *testing.T) {
	require.Equal(t, makeAbsoluteURL("/a", "https://example.com"), "https://example.com/a")
	require.Equal(t, makeAbsoluteURL("https://foo.com/a/b", "https://bar.com"), "https://foo.com/a/b")
}

var docTests = []struct {
	fn       func(*goquery.Document) bool
	file     string
	expected bool
}{
	{docIsPreLogin, "example/pre-login.html", true},
	{docIsLogin, "example/pre-login.html", false},
	{docIsLogin, "example/login.html", true},
	{docIsLogin, "example/login2.html", true},
	{docIsLogin, "example/otp.html", false},
	{docIsLogin, "example/swipe.html", false},
	{docIsLogin, "example/form-redirect.html", false},
	{docIsLogin, "example/webauthn.html", false},
	{docIsOTP, "example/login.html", false},
	{docIsOTP, "example/otp.html", true},
	{docIsOTP, "example/swipe.html", false},
	{docIsOTP, "example/form-redirect.html", false},
	{docIsOTP, "example/webauthn.html", false},
	{docIsToken, "example/token.html", true},
	{docIsSwipe, "example/login.html", false},
	{docIsSwipe, "example/otp.html", false},
	{docIsSwipe, "example/swipe.html", true},
	{docIsSwipe, "example/form-redirect.html", false},
	{docIsSwipe, "example/webauthn.html", false},
	{docIsFormRedirect, "example/login.html", false},
	{docIsFormRedirect, "example/otp.html", false},
	{docIsFormRedirect, "example/swipe.html", false},
	{docIsFormRedirect, "example/form-redirect.html", true},
	{docIsFormRedirect, "example/webauthn.html", false},
	{docIsWebAuthn, "example/login.html", false},
	{docIsWebAuthn, "example/otp.html", false},
	{docIsWebAuthn, "example/swipe.html", false},
	{docIsWebAuthn, "example/form-redirect.html", false},
	{docIsWebAuthn, "example/webauthn.html", true},
	{docIsPingMessage, "example/password-expired.html", true},
	{docIsSelectDevice, "example/devices.html", true},
	{docIsChallenge, "example/challenge.html", true},
}

func TestDocTypes(t *testing.T) {
	for _, tt := range docTests {
		data, err := ioutil.ReadFile(tt.file)
		require.Nil(t, err)

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
		require.Nil(t, err)

		if tt.fn(doc) != tt.expected {
			t.Errorf("expect doc check of %v to be %v", tt.file, tt.expected)
		}
	}
}

func TestNew(t *testing.T) {
	account := &cfg.IDPAccount{
		Name:                 "default",
		URL:                  "https://example.com",
		Username:             "username",
		Provider:             "Ping",
		MFA:                  "Auto",
		Timeout:              10,
		AmazonWebservicesURN: "urn:amazon:webservices",
		SessionDuration:      3600,
		Profile:              "default",
		Region:               "us-east-1",
	}

	client, err := New(account)
	require.Nil(t, err)

	require.Equal(t, account, client.idpAccount)
	require.IsType(t, client.client, &provider.HTTPClient{})
	require.NotNil(t, client.client)
}

func TestHandlePreLogin(t *testing.T) {
	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), &loginDetails)

	data, err := ioutil.ReadFile("example/pre-login.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	_, req, err := ac.handlePreLogin(ctx, doc)
	require.Nil(t, err)

	b, err := ioutil.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "subject=fdsa")
}

func TestHandlePreLoginNoContext(t *testing.T) {
	ac := Client{}

	data, err := ioutil.ReadFile("example/pre-login.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	_, _, err = ac.handlePreLogin(context.Background(), doc)
	require.Error(t, err, "no context value for 'login'")
}

func TestHandleLogin(t *testing.T) {
	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), &loginDetails)

	data, err := ioutil.ReadFile("example/login.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	_, req, err := ac.handleLogin(ctx, doc)
	require.Nil(t, err)

	b, err := ioutil.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "pf.username=fdsa")
	require.Contains(t, s, "pf.pass=secret")
}

func TestHandleSelectDevice(t *testing.T) {
	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("Choose", "Select device", []string{"Phone", "Security Key"}).Return(1)

	resp = &http.Response{
		Request: &http.Request{
			URL: &url.URL{
				Scheme:  "https",
				Host:    "example.com",
				Path:    "/auth",
				RawPath: "/auth",
			},
		},
	}

	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), &loginDetails)

	data, err := ioutil.ReadFile("example/devices.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	_, req, err := ac.handleSelectDevice(ctx, doc)
	require.Nil(t, err)

	b, err := ioutil.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "deviceId=555")
	require.Equal(t, resp.Request.URL.String(), req.URL.String())
}

func TestHandleSelectDevicePreSelected(t *testing.T) {
	resp = &http.Response{
		Request: &http.Request{
			URL: &url.URL{
				Scheme:  "https",
				Host:    "example.com",
				Path:    "/auth",
				RawPath: "/auth",
			},
		},
	}

	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username:  "fdsa",
		Password:  "secret",
		URL:       "https://example.com/foo",
		MFADevice: "Security Key",
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), &loginDetails)

	data, err := ioutil.ReadFile("example/devices.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	_, req, err := ac.handleSelectDevice(ctx, doc)
	require.Nil(t, err)

	b, err := ioutil.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "deviceId=555")
	require.Equal(t, resp.Request.URL.String(), req.URL.String())
}

func TestHandleToken(t *testing.T) {
	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("Password", "Enter Token Code (PIN + Token / Passcode for RSA)").Return("5309")

	data, err := ioutil.ReadFile("example/token.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), &loginDetails)

	_, req, err := ac.handleToken(ctx, doc)
	require.Nil(t, err)

	b, err := ioutil.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "pf.pass=5309")
}

func TestHandleOTP(t *testing.T) {
	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("Password", "Enter passcode").Return("5309")

	data, err := ioutil.ReadFile("example/otp.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), &loginDetails)

	_, req, err := ac.handleOTP(ctx, doc)
	require.Nil(t, err)

	b, err := ioutil.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "otp=5309")
}

func TestHandleOTPWithArgument(t *testing.T) {
	data, err := ioutil.ReadFile("example/otp.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
		MFAToken: "5309",
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), &loginDetails)

	_, req, err := ac.handleOTP(ctx, doc)
	require.Nil(t, err)

	b, err := ioutil.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "otp=5309")
}

func TestHandleFormRedirect(t *testing.T) {
	data, err := ioutil.ReadFile("example/form-redirect.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	_, req, err := ac.handleFormRedirect(context.Background(), doc)
	require.Nil(t, err)

	b, err := ioutil.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "ppm_request=secret")
	require.Contains(t, s, "idp_account_id=some-uuid")
}

func TestHandleChallenge(t *testing.T) {
	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("Password", "Enter Next Token Code (PIN + Token / Passcode for RSA)").Return("12345")

	data, err := ioutil.ReadFile("example/challenge.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), &loginDetails)
	_, req, err := ac.handleChallenge(ctx, doc)
	require.Nil(t, err)

	b, err := ioutil.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "pf.ok=clicked")
	require.Contains(t, s, "pf.challengeResponse=12345")
}

func TestHandleWebAuthn(t *testing.T) {
	data, err := ioutil.ReadFile("example/webauthn.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	_, req, err := ac.handleWebAuthn(context.Background(), doc)
	require.Nil(t, err)

	b, err := ioutil.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "isWebAuthnSupportedByBrowser=true")
}

func TestHandlePasswordExpired(t *testing.T) {
	data, err := ioutil.ReadFile("example/password-expired.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	_, _, err = ac.handlePingMessage(context.Background(), doc)
	require.Error(t, err, "Your password is expired and must be changed.")
}

func TestCheckForDevices(t *testing.T) {
	req := checkForDevices()

	resp = &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{"test=value; Domain=example.com; Path=/; Secure; HttpOnly"},
		},
	}
	require.Equal(t, "https://authenticator.pingone.com/pingid/ppm/devices", req.URL.String())
	require.Equal(t, "GET", req.Method)

	var cookie *http.Cookie = nil
	for _, c := range resp.Cookies() {
		if c.Name == "test" {
			cookie = c
			break
		}
	}
	require.NotNil(t, cookie)
	require.Equal(t, "test", cookie.Name)
	require.Equal(t, "value", cookie.Value)
}

func TestAddCookies(t *testing.T) {
	req, err := http.NewRequest("GET", "https://www.example.com", nil)
	require.Nil(t, err)

	cookies := []*http.Cookie{
		{
			Name:   "test1",
			Value:  "val1",
			Domain: "example.com",
		},
		{
			Name:   "test2",
			Value:  "val2",
			Domain: "test.com",
		},
		{
			Name:   "test3",
			Value:  "val3",
			Domain: "www.example.com",
		},
	}

	addCookies(req, cookies)

	require.Len(t, req.Cookies(), 2)

	for _, c := range req.Cookies() {
		if c.Name == "test2" && c.Value == "val2" {
			require.Fail(t, "Request should not contain cookie test2")
		}
	}
}

func TestContains(t *testing.T) {
	items := []string{"item1", "item2", "item3"}
	require.True(t, contains(items, "item2"))
	require.False(t, contains(items, "item5"))
}
