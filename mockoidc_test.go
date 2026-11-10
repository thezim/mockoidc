package mockoidc_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/thezim/mockoidc"
)

const TestNow = 1234567890

// A custom client that doesn't automatically follow redirects
var httpClient = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func TestRun(t *testing.T) {
	setTime()
	defer resetTime()

	m, err := mockoidc.Run()
	assert.NoError(t, err)
	defer m.Shutdown()

	// ************************************************************************
	// Stage 0: Get Discovery documents
	// ************************************************************************
	discoveryReq, err := http.NewRequest(http.MethodGet, m.DiscoveryEndpoint(), nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(discoveryReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	jwksReq, err := http.NewRequest(http.MethodGet, m.JWKSEndpoint(), nil)
	assert.NoError(t, err)

	resp, err = httpClient.Do(jwksReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	config := m.Config()

	// ************************************************************************
	// Stage 1: Emulate client to IdP request
	// ************************************************************************
	const (
		state = "abcdef1234567890"
		nonce = "0987654321fedcba"
		code  = "asdflkjh12340987"
	)
	authorizeQuery := url.Values{}
	authorizeQuery.Set("client_id", config.ClientID)
	authorizeQuery.Set("scope", "openid email profile groups")
	authorizeQuery.Set("response_type", "code")
	authorizeQuery.Set("redirect_uri", "http://127.0.0.1/oauth2/callback")
	authorizeQuery.Set("state", state)
	authorizeQuery.Set("nonce", nonce)

	codeVerifier := "sum"
	challenge, err := mockoidc.GenerateCodeChallenge(mockoidc.CodeChallengeMethodS256, codeVerifier)
	assert.NoError(t, err)
	authorizeQuery.Set("code_challenge", challenge)
	authorizeQuery.Set("code_challenge_method", mockoidc.CodeChallengeMethodS256)

	authorizeURL, err := url.Parse(m.AuthorizationEndpoint())
	assert.NoError(t, err)
	authorizeURL.RawQuery = authorizeQuery.Encode()

	authorizeReq, err := http.NewRequest(http.MethodGet, authorizeURL.String(), nil)
	assert.NoError(t, err)

	m.QueueCode(code)
	resp, err = httpClient.Do(authorizeReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	appRedirect, err := url.Parse(resp.Header.Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, code, appRedirect.Query().Get("code"))
	assert.Equal(t, state, appRedirect.Query().Get("state"))

	// ************************************************************************
	// Stage 2: Emulate appRedirect handling token endpoint call
	// ************************************************************************
	tokenForm := url.Values{}
	tokenForm.Set("client_id", config.ClientID)
	tokenForm.Set("client_secret", config.ClientSecret)
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", appRedirect.Query().Get("code"))
	tokenForm.Set("code_verifier", codeVerifier)

	tokenReq, err := http.NewRequest(
		http.MethodPost, m.TokenEndpoint(), bytes.NewBufferString(tokenForm.Encode()))
	assert.NoError(t, err)
	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err = httpClient.Do(tokenReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)

	tokens := make(map[string]interface{})
	err = json.Unmarshal(body, &tokens)
	assert.NoError(t, err)

	_, err = m.Keypair.VerifyJWT(tokens["access_token"].(string), m.Now)
	assert.NoError(t, err)
	_, err = m.Keypair.VerifyJWT(tokens["refresh_token"].(string), m.Now)
	assert.NoError(t, err)
	idToken, err := m.Keypair.VerifyJWT(tokens["id_token"].(string), m.Now)
	assert.NoError(t, err)

	// The nonce we set initially is in our ID Token
	claims, ok := idToken.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, nonce, claims["nonce"])

	// ************************************************************************
	// Stage 3: Use the Access Token for a Userinfo call
	// ************************************************************************
	userinfoReq, err := http.NewRequest(http.MethodGet, m.UserinfoEndpoint(), nil)
	assert.NoError(t, err)
	userinfoReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokens["id_token"]))

	resp, err = httpClient.Do(userinfoReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// ************************************************************************
	// Stage 4: Expired Tokens don't work
	// ************************************************************************
	m.FastForward(config.AccessTTL + 1)

	expiredReq, err := http.NewRequest(http.MethodGet, m.UserinfoEndpoint(), nil)
	assert.NoError(t, err)
	userinfoReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokens["id_token"]))

	resp, err = httpClient.Do(expiredReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// ************************************************************************
	// Stage 5: We can refresh them
	// ************************************************************************
	refreshForm := url.Values{}
	refreshForm.Set("client_id", config.ClientID)
	refreshForm.Set("client_secret", config.ClientSecret)
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", tokens["refresh_token"].(string))

	refreshReq, err := http.NewRequest(
		http.MethodPost, m.TokenEndpoint(), bytes.NewBufferString(refreshForm.Encode()))
	assert.NoError(t, err)
	refreshReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err = httpClient.Do(refreshReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()
	refreshBody, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)

	refreshedTokens := make(map[string]interface{})
	err = json.Unmarshal(refreshBody, &refreshedTokens)
	assert.NoError(t, err)

	_, err = m.Keypair.VerifyJWT(refreshedTokens["access_token"].(string), m.Now)
	assert.NoError(t, err)
	_, err = m.Keypair.VerifyJWT(refreshedTokens["refresh_token"].(string), m.Now)
	assert.NoError(t, err)
	refreshedIDToken, err := m.Keypair.VerifyJWT(refreshedTokens["id_token"].(string), m.Now)
	assert.NoError(t, err)

	// The nonce we set initially is STILL in our ID Token
	refreshedClaims, ok := refreshedIDToken.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, nonce, refreshedClaims["nonce"])

	// ************************************************************************
	// Stage 6: Access Token works again
	// ************************************************************************
	userinfoReq2, err := http.NewRequest(http.MethodGet, m.UserinfoEndpoint(), nil)
	assert.NoError(t, err)
	userinfoReq2.Header.Add("Authorization",
		fmt.Sprintf("Bearer %s", refreshedTokens["id_token"]))

	resp, err = httpClient.Do(userinfoReq2)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// ************************************************************************
	// Stage 7: Refresh Tokens expire and won't refresh
	// ************************************************************************
	m.FastForward(config.RefreshTTL)

	refreshForm2 := url.Values{}
	refreshForm2.Set("client_id", config.ClientID)
	refreshForm2.Set("client_secret", config.ClientSecret)
	refreshForm2.Set("grant_type", "refresh_token")
	refreshForm2.Set("refresh_token", tokens["refresh_token"].(string))

	refreshReq2, err := http.NewRequest(
		http.MethodPost, m.TokenEndpoint(), bytes.NewBufferString(tokenForm.Encode()))
	assert.NoError(t, err)
	refreshReq2.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err = httpClient.Do(refreshReq2)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// ************************************************************************
	// Stage 8: RP-Initiated Logout
	// ************************************************************************
	logoutQuery := url.Values{}
	logoutQuery.Set("id_token_hint", tokens["id_token"].(string))
	logoutQuery.Set("post_logout_redirect_uri", "http://127.0.0.1/oauth2/sign_out")
	logoutQuery.Set("state", state)

	logoutReq, err := http.NewRequest(
		http.MethodGet, m.EndSessionEndpoint()+"?"+logoutQuery.Encode(), nil)
	assert.NoError(t, err)

	resp, err = httpClient.Do(logoutReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	logoutRedirect, err := url.Parse(resp.Header.Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1/oauth2/sign_out",
		logoutRedirect.Scheme+"://"+logoutRedirect.Host+logoutRedirect.Path)
	assert.Equal(t, state, logoutRedirect.Query().Get("state"))

	// The session behind the ID Token hint was invalidated
	_, err = m.SessionStore.GetSessionByID(code)
	assert.Error(t, err)

	// The /oidc/logout alias works the same way and is idempotent
	aliasReq, err := http.NewRequest(
		http.MethodGet, m.LogoutEndpoint()+"?"+logoutQuery.Encode(), nil)
	assert.NoError(t, err)

	resp, err = httpClient.Do(aliasReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, resp.StatusCode)
}

func TestRun_ForwardedHeaders(t *testing.T) {
	setTime()
	defer resetTime()

	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)
	m.UseForwardedHeaders = true

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)

	err = m.Start(ln, nil)
	assert.NoError(t, err)
	defer m.Shutdown()

	const (
		publicHost = "mockoidc.example.com"
		state      = "abcdef1234567890"
		nonce      = "0987654321fedcba"
	)

	// Emulate the headers a load balancer terminating TLS sends to us.
	forwarded := func(req *http.Request) *http.Request {
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", publicHost)
		return req
	}

	publicIssuer := "https://" + publicHost + "/oidc"

	// **********************************************************************
	// Stage 0: Discovery advertises the public https URLs
	// **********************************************************************
	discoveryReq, err := http.NewRequest(http.MethodGet, m.DiscoveryEndpoint(), nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(forwarded(discoveryReq))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	discovery := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&discovery)
	resp.Body.Close()
	assert.NoError(t, err)

	assert.Equal(t, publicIssuer, discovery["issuer"])
	assert.Equal(t, publicIssuer+"/authorize", discovery["authorization_endpoint"])
	assert.Equal(t, publicIssuer+"/token", discovery["token_endpoint"])
	assert.Equal(t, publicIssuer+"/.well-known/jwks.json", discovery["jwks_uri"])
	assert.Equal(t, publicIssuer+"/endsession", discovery["end_session_endpoint"])

	// **********************************************************************
	// Stage 1: Emulate client to IdP request
	// **********************************************************************
	authorizeQuery := url.Values{}
	authorizeQuery.Set("client_id", m.ClientID)
	authorizeQuery.Set("scope", "openid email profile")
	authorizeQuery.Set("response_type", "code")
	authorizeQuery.Set("redirect_uri", "http://127.0.0.1/oauth2/callback")
	authorizeQuery.Set("state", state)
	authorizeQuery.Set("nonce", nonce)

	authorizeURL, err := url.Parse(m.AuthorizationEndpoint())
	assert.NoError(t, err)
	authorizeURL.RawQuery = authorizeQuery.Encode()

	authorizeReq, err := http.NewRequest(http.MethodGet, authorizeURL.String(), nil)
	assert.NoError(t, err)

	resp, err = httpClient.Do(forwarded(authorizeReq))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	appRedirect, err := url.Parse(resp.Header.Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, state, appRedirect.Query().Get("state"))

	// **********************************************************************
	// Stage 2: Tokens carry the same public issuer as discovery
	// **********************************************************************
	tokenForm := url.Values{}
	tokenForm.Set("client_id", m.ClientID)
	tokenForm.Set("client_secret", m.ClientSecret)
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", appRedirect.Query().Get("code"))

	tokenReq, err := http.NewRequest(
		http.MethodPost, m.TokenEndpoint(), strings.NewReader(tokenForm.Encode()))
	assert.NoError(t, err)
	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err = httpClient.Do(forwarded(tokenReq))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	tokens := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&tokens)
	resp.Body.Close()
	assert.NoError(t, err)

	for _, key := range []string{"access_token", "id_token", "refresh_token"} {
		token, err := m.Keypair.VerifyJWT(tokens[key].(string), m.Now)
		assert.NoError(t, err)

		claims, ok := token.Claims.(jwt.MapClaims)
		assert.True(t, ok)
		assert.Equal(t, publicIssuer, claims["iss"])
	}
}

func TestMockOIDC_Addr_HostOverride(t *testing.T) {
	m := &mockoidc.MockOIDC{
		Server: &http.Server{
			Addr: "127.0.0.1:8080",
		},
		Host: "mockoidc.example.com",
	}

	assert.Equal(t, "http://mockoidc.example.com", m.Addr())
	assert.Equal(t, "http://mockoidc.example.com/oidc", m.Issuer())

	// A full URL also overrides the scheme, since TLS may be terminated
	// by a proxy in front of MockOIDC.
	m.Host = "https://mockoidc.example.com"
	assert.Equal(t, "https://mockoidc.example.com", m.Addr())
	assert.Equal(t, "https://mockoidc.example.com/oidc", m.Issuer())
	assert.Equal(t, "https://mockoidc.example.com/oidc", m.Config().Issuer)
	assert.Equal(t, "https://mockoidc.example.com/oidc/token", m.TokenEndpoint())

	// Trailing slashes don't end up in URLs
	m.Host = "https://mockoidc.example.com/"
	assert.Equal(t, "https://mockoidc.example.com", m.Addr())
}

func TestMockOIDC_Config(t *testing.T) {
	m, err := mockoidc.Run()
	assert.NoError(t, err)
	defer m.Shutdown()

	cfg := m.Config()
	assert.Equal(t, m.ClientID, cfg.ClientID)
	assert.Equal(t, m.ClientSecret, cfg.ClientSecret)
	assert.Equal(t, m.Issuer(), cfg.Issuer)
	assert.Equal(t, m.AccessTTL, cfg.AccessTTL)
	assert.Equal(t, m.RefreshTTL, cfg.RefreshTTL)
	assert.Equal(t, m.CodeChallengeMethodsSupported, cfg.CodeChallengeMethodsSupported)
}

func TestMockOIDC_QueueError(t *testing.T) {
	m, err := mockoidc.Run()
	assert.NoError(t, err)
	defer m.Shutdown()

	type handlerError struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}

	m.QueueError(&mockoidc.ServerError{
		Code:        http.StatusInternalServerError,
		Error:       mockoidc.InternalServerError,
		Description: "Discovery Error",
	})

	m.QueueError(&mockoidc.ServerError{
		Code:        http.StatusBadRequest,
		Error:       mockoidc.InvalidRequest,
		Description: "Authorize Error",
	})

	// First Queued Error
	discoveryReq, err := http.NewRequest(http.MethodGet, m.DiscoveryEndpoint(), nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(discoveryReq)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	var discoveryResp handlerError
	err = json.NewDecoder(resp.Body).Decode(&discoveryResp)
	assert.NoError(t, err)
	assert.Equal(t, "Discovery Error", discoveryResp.Description)

	// Second Queued Error
	authorizeReq, err := http.NewRequest(http.MethodGet, m.AuthorizationEndpoint(), nil)
	assert.NoError(t, err)

	resp, err = httpClient.Do(authorizeReq)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var authorizeResp handlerError
	err = json.NewDecoder(resp.Body).Decode(&authorizeResp)
	assert.NoError(t, err)
	assert.Equal(t, "Authorize Error", authorizeResp.Description)

	// No Errors Queued
	jwksReq, err := http.NewRequest(http.MethodGet, m.JWKSEndpoint(), nil)
	assert.NoError(t, err)

	resp, err = httpClient.Do(jwksReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestMockOIDC_AddMiddleware(t *testing.T) {
	before := 0
	after := 0
	flagger := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			before = before + 1
			next.ServeHTTP(rw, req)
			after = after + 1
		})
	}

	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)

	const chains = 5
	for i := 0; i < chains; i++ {
		err = m.AddMiddleware(flagger)
		assert.NoError(t, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)

	err = m.Start(ln, nil)
	assert.NoError(t, err)
	defer m.Shutdown()

	// middleware not run
	assert.Equal(t, 0, before)
	assert.Equal(t, 0, after)

	req, err := http.NewRequest(http.MethodGet, m.DiscoveryEndpoint(), nil)
	assert.NoError(t, err)
	_, err = httpClient.Do(req)
	assert.NoError(t, err)

	// middleware run around the request
	assert.Equal(t, chains, before)
	assert.Equal(t, chains, after)

	// no new middleware allowed after starting
	err = m.AddMiddleware(flagger)
	assert.Error(t, err)
}

func TestMockOIDC_FastForward(t *testing.T) {
	setTime()
	defer resetTime()

	m := &mockoidc.MockOIDC{}

	ff1 := m.FastForward(time.Duration(123))
	assert.Equal(t, time.Duration(123), ff1)
	assert.Equal(t, mockoidc.NowFunc().Add(time.Duration(123)), m.Now())

	ff2 := m.FastForward(time.Duration(456))
	assert.Equal(t, time.Duration(579), ff2)
	assert.Equal(t, mockoidc.NowFunc().Add(time.Duration(579)), m.Now())
}

func setTime() {
	mockoidc.NowFunc = func() time.Time {
		return time.Unix(TestNow, 0)
	}
	jwt.WithTimeFunc(func() time.Time {
		return time.Unix(TestNow, 0)
	})
}

func resetTime() {
	mockoidc.NowFunc = time.Now
	jwt.WithTimeFunc(time.Now)
}
