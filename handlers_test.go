package mockoidc_test

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/thezim/mockoidc"
)

func TestMockOIDC_Authorize(t *testing.T) {
	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)

	data := url.Values{}
	data.Set("scope", "openid email profile")
	data.Set("response_type", "code")
	data.Set("redirect_uri", "example.com")
	data.Set("state", "testState")
	data.Set("client_id", m.ClientID)
	data.Set("code_challenge", "somehash")
	data.Set("code_challenge_method", "S256")
	assert.HTTPError(t, m.Authorize, http.MethodGet, mockoidc.AuthorizationEndpoint, nil)

	// valid request
	assert.HTTPStatusCode(t, m.Authorize, http.MethodGet,
		mockoidc.AuthorizationEndpoint, data, http.StatusFound)

	// Bad client ID
	data.Set("client_id", "wrong_id")
	assert.HTTPStatusCode(t, m.Authorize, http.MethodGet,
		mockoidc.AuthorizationEndpoint, data, http.StatusUnauthorized)
	assert.HTTPBodyContains(t, m.Authorize, http.MethodGet,
		mockoidc.AuthorizationEndpoint, data, mockoidc.InvalidClient)

	// Bad code challenge method
	data.Set("client_id", m.ClientID)
	data.Set("code_challenge_method", "does not exist")
	assert.HTTPStatusCode(t, m.Authorize, http.MethodGet,
		mockoidc.AuthorizationEndpoint, data, http.StatusBadRequest)
	assert.HTTPBodyContains(t, m.Authorize, http.MethodGet,
		mockoidc.AuthorizationEndpoint, data, mockoidc.InvalidRequest)

	// Missing required form values
	for key := range data {
		if key == "code_challenge" || key == "code_challenge_method" {
			// Skip not required fields
			continue
		}

		t.Run(key, func(t *testing.T) {
			badData, _ := url.ParseQuery(data.Encode())
			badData.Del(key)

			assert.HTTPStatusCode(t, m.Authorize, http.MethodGet,
				mockoidc.AuthorizationEndpoint, badData, http.StatusBadRequest)
			assert.HTTPBodyContains(t, m.Authorize, http.MethodGet,
				mockoidc.AuthorizationEndpoint, badData, mockoidc.InvalidRequest)
		})
	}
}

func TestMockOIDC_Token_CodeGrant(t *testing.T) {
	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)

	session, _ := m.SessionStore.NewSession(
		"openid email profile", "nonce", mockoidc.DefaultUser(), "", "")

	assert.HTTPError(t, m.Token, http.MethodPost, mockoidc.TokenEndpoint, nil)

	data := url.Values{}
	data.Set("client_id", m.ClientID)
	data.Set("client_secret", m.ClientSecret)
	data.Set("code", session.SessionID)
	data.Set("grant_type", "authorization_code")

	// Missing parameters result in BadRequest
	for key := range data {
		t.Run(key, func(t *testing.T) {
			badData, _ := url.ParseQuery(data.Encode())
			badData.Del(key)

			rr := testResponse(t, mockoidc.TokenEndpoint, m.Token, http.MethodPost, badData)
			assert.Equal(t, http.StatusBadRequest, rr.Code)

			body, err := ioutil.ReadAll(rr.Body)
			assert.NoError(t, err)
			assert.Contains(t, string(body), mockoidc.InvalidRequest)
		})
	}

	// wrong values won't work
	for key := range data {
		t.Run(key, func(t *testing.T) {
			badData, err := url.ParseQuery(data.Encode())
			assert.NoError(t, err)

			badData.Set(key, "WRONG")
			rr := testResponse(t, mockoidc.TokenEndpoint, m.Token, http.MethodPost, badData)
			if key == "grant_type" {
				assert.Equal(t, http.StatusBadRequest, rr.Code)
			} else {
				assert.Equal(t, http.StatusUnauthorized, rr.Code)
			}
		})
	}

	// good request; check responses
	rr := testResponse(t, mockoidc.TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, http.StatusOK, rr.Code)

	tokenResp := make(map[string]interface{})
	err = getJSON(rr, &tokenResp)
	assert.NoError(t, err)

	assert.Contains(t, tokenResp, "access_token")
	assert.Contains(t, tokenResp, "id_token")
	assert.Contains(t, tokenResp, "refresh_token")
	assert.Contains(t, tokenResp, "token_type")
	assert.Contains(t, tokenResp, "expires_in")

	for _, key := range []string{
		"access_token",
		"refresh_token",
		"id_token",
	} {
		t.Run(key, func(t *testing.T) {
			_, err := m.Keypair.VerifyJWT(tokenResp[key].(string), m.Now)
			assert.NoError(t, err)
		})
	}

	// duplicate attempts are rejects
	rrDup := testResponse(t, mockoidc.TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, http.StatusUnauthorized, rrDup.Code)
}

func TestMockOIDC_Token_CodeGrant_CodeChallengePlain(t *testing.T) {
	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)

	codeChallenge, err := mockoidc.GenerateCodeChallenge(mockoidc.CodeChallengeMethodPlain, "sum")
	assert.NoError(t, err)
	session, _ := m.SessionStore.NewSession(
		"openid email profile", "nonce", mockoidc.DefaultUser(),
		codeChallenge, mockoidc.CodeChallengeMethodPlain)

	assert.HTTPError(t, m.Token, http.MethodPost, mockoidc.TokenEndpoint, nil)

	data := url.Values{}
	data.Set("client_id", m.ClientID)
	data.Set("client_secret", m.ClientSecret)
	data.Set("code", session.SessionID)
	data.Set("grant_type", "authorization_code")
	data.Set("code_verifier", "sum")

	// good request; good response
	rr := testResponse(t, mockoidc.TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, http.StatusOK, rr.Code)

	tokenResp := make(map[string]interface{})
	err = getJSON(rr, &tokenResp)
	assert.NoError(t, err)

	// bad request; no verifier provided
	badData, _ := url.ParseQuery(data.Encode())
	badData.Del("code_verifier")

	rr = testResponse(t, mockoidc.TokenEndpoint, m.Token, http.MethodPost, badData)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	body, err := ioutil.ReadAll(rr.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), mockoidc.InvalidGrant)

	// bad request; bad verifier provided
	badData, _ = url.ParseQuery(data.Encode())
	badData.Set("code_verifier", "WRONG")

	rr = testResponse(t, mockoidc.TokenEndpoint, m.Token, http.MethodPost, badData)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	body, err = ioutil.ReadAll(rr.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), mockoidc.InvalidGrant)
}

func TestMockOIDC_Token_CodeGrant_CodeChallengeHash(t *testing.T) {
	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)

	codeChallenge, err := mockoidc.GenerateCodeChallenge(mockoidc.CodeChallengeMethodS256, "sum")
	assert.NoError(t, err)
	session, _ := m.SessionStore.NewSession(
		"openid email profile", "nonce", mockoidc.DefaultUser(),
		codeChallenge, mockoidc.CodeChallengeMethodS256)

	assert.HTTPError(t, m.Token, http.MethodPost, mockoidc.TokenEndpoint, nil)

	data := url.Values{}
	data.Set("client_id", m.ClientID)
	data.Set("client_secret", m.ClientSecret)
	data.Set("code", session.SessionID)
	data.Set("grant_type", "authorization_code")
	data.Set("code_verifier", "sum")

	// good request; good response
	rr := testResponse(t, mockoidc.TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, http.StatusOK, rr.Code)

	tokenResp := make(map[string]interface{})
	err = getJSON(rr, &tokenResp)
	assert.NoError(t, err)

	// bad request; no verifier provided
	badData, _ := url.ParseQuery(data.Encode())
	badData.Del("code_verifier")

	rr = testResponse(t, mockoidc.TokenEndpoint, m.Token, http.MethodPost, badData)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	body, err := ioutil.ReadAll(rr.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), mockoidc.InvalidGrant)

	// bad request; bad verifier provided
	badData, _ = url.ParseQuery(data.Encode())
	badData.Set("code_verifier", "WRONG")

	rr = testResponse(t, mockoidc.TokenEndpoint, m.Token, http.MethodPost, badData)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	body, err = ioutil.ReadAll(rr.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), mockoidc.InvalidGrant)
}

func TestMockOIDC_Token_RefreshGrant(t *testing.T) {
	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)

	session, _ := m.SessionStore.NewSession(
		"openid email profile", "sessionNonce", mockoidc.DefaultUser(), "", "")
	refreshToken, _ := session.RefreshToken(m.Config(), m.Keypair, m.Now())

	assert.HTTPError(t, m.Token, http.MethodPost, mockoidc.TokenEndpoint, nil)

	data := url.Values{}
	data.Set("client_id", m.ClientID)
	data.Set("client_secret", m.ClientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	// good request; check responses
	rr := testResponse(t, mockoidc.TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, http.StatusOK, rr.Code)

	tokenResp := make(map[string]interface{})
	err = getJSON(rr, &tokenResp)
	assert.NoError(t, err)

	assert.Contains(t, tokenResp, "access_token")
	assert.Contains(t, tokenResp, "id_token")
	assert.Contains(t, tokenResp, "refresh_token")
	assert.Contains(t, tokenResp, "token_type")
	assert.Contains(t, tokenResp, "expires_in")

	for _, key := range []string{
		"access_token",
		"refresh_token",
		"id_token",
	} {
		t.Run(key, func(t *testing.T) {
			_, err := m.Keypair.VerifyJWT(tokenResp[key].(string), m.Now)
			assert.NoError(t, err)
		})
	}

	// expired refresh token
	expiredToken, err := session.RefreshToken(
		m.Config(), m.Keypair, m.Now().Add(time.Hour*time.Duration(-24)))
	assert.NoError(t, err)

	data.Set("refresh_token", expiredToken)

	rr = testResponse(t, mockoidc.TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	body, err := ioutil.ReadAll(rr.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), mockoidc.InvalidRequest)
}

func TestMockOIDC_Logout(t *testing.T) {
	for _, endpoint := range []string{mockoidc.LogoutEndpoint, mockoidc.EndSessionEndpoint} {
		t.Run(endpoint, func(t *testing.T) {
			testLogout(t, endpoint)
		})
	}
}

func testLogout(t *testing.T, endpoint string) {
	t.Helper()

	newServer := func(t *testing.T) *mockoidc.MockOIDC {
		t.Helper()
		m, err := mockoidc.NewServer(nil)
		assert.NoError(t, err)
		m.Server = &http.Server{Addr: "127.0.0.1:8080"}
		return m
	}

	newIDToken := func(t *testing.T, m *mockoidc.MockOIDC, issuedAt time.Time) (*mockoidc.Session, string) {
		t.Helper()
		session, err := m.SessionStore.NewSession(
			"openid email profile", "nonce", mockoidc.DefaultUser(), "", "")
		assert.NoError(t, err)

		idToken, err := session.IDToken(m.Config(), m.Keypair, issuedAt)
		assert.NoError(t, err)
		return session, idToken
	}

	// A GET request redirects to the post_logout_redirect_uri and echoes state
	m := newServer(t)
	session, idToken := newIDToken(t, m, m.Now())

	data := url.Values{}
	data.Set("id_token_hint", idToken)
	data.Set("post_logout_redirect_uri", "http://127.0.0.1/oauth2/sign_out")
	data.Set("state", "testState")

	rr := testResponse(t, endpoint, m.Logout, http.MethodGet, data)
	assert.Equal(t, http.StatusFound, rr.Code)

	redirect, err := url.Parse(rr.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1/oauth2/sign_out",
		redirect.Scheme+"://"+redirect.Host+redirect.Path)
	assert.Equal(t, "testState", redirect.Query().Get("state"))

	// The session referenced by the hint was invalidated
	_, err = m.SessionStore.GetSessionByID(session.SessionID)
	assert.Error(t, err)

	// POST requests work too
	m = newServer(t)
	session, idToken = newIDToken(t, m, m.Now())
	data.Set("id_token_hint", idToken)

	rr = testResponse(t, endpoint, m.Logout, http.MethodPost, data)
	assert.Equal(t, http.StatusFound, rr.Code)

	_, err = m.SessionStore.GetSessionByID(session.SessionID)
	assert.Error(t, err)

	// Expired ID Token hints are still accepted
	m = newServer(t)
	session, idToken = newIDToken(t, m, m.Now().Add(time.Duration(-24)*time.Hour))
	data.Set("id_token_hint", idToken)

	rr = testResponse(t, endpoint, m.Logout, http.MethodGet, data)
	assert.Equal(t, http.StatusFound, rr.Code)

	_, err = m.SessionStore.GetSessionByID(session.SessionID)
	assert.Error(t, err)

	// Hints that don't verify are ignored
	m = newServer(t)
	session, _ = newIDToken(t, m, m.Now())
	data.Set("id_token_hint", "not-a-token")

	rr = testResponse(t, endpoint, m.Logout, http.MethodGet, data)
	assert.Equal(t, http.StatusFound, rr.Code)

	_, err = m.SessionStore.GetSessionByID(session.SessionID)
	assert.NoError(t, err)

	// Without a post_logout_redirect_uri a logout page is returned
	m = newServer(t)
	rr = testResponse(t, endpoint, m.Logout, http.MethodGet, url.Values{})
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Logged out")

	// Malformed post_logout_redirect_uris are rejected
	data = url.Values{}
	data.Set("post_logout_redirect_uri", "://invalid")

	rr = testResponse(t, endpoint, m.Logout, http.MethodGet, data)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), mockoidc.InvalidRequest)
}

func TestMockOIDC_Discovery(t *testing.T) {
	m := &mockoidc.MockOIDC{
		Server: &http.Server{
			Addr: "127.0.0.1:8080",
		},
		CodeChallengeMethodsSupported: []string{"some_random_value"},
	}
	recorder := httptest.NewRecorder()
	m.Discovery(recorder, &http.Request{})

	oidcCfg := make(map[string]interface{})
	err := getJSON(recorder, &oidcCfg)
	assert.NoError(t, err)

	assert.Equal(t, oidcCfg["issuer"], m.Issuer())
	assert.Equal(t, oidcCfg["authorization_endpoint"], m.AuthorizationEndpoint())
	assert.Equal(t, oidcCfg["token_endpoint"], m.TokenEndpoint())
	assert.Equal(t, oidcCfg["userinfo_endpoint"], m.UserinfoEndpoint())
	assert.Equal(t, oidcCfg["jwks_uri"], m.JWKSEndpoint())
	assert.Equal(t, oidcCfg["end_session_endpoint"], m.EndSessionEndpoint())
	assert.ElementsMatch(t, oidcCfg["code_challenge_methods_supported"], m.CodeChallengeMethodsSupported)
}

func TestMockOIDC_Discovery_ForwardedHeaders(t *testing.T) {
	m := &mockoidc.MockOIDC{
		Server: &http.Server{
			Addr: "127.0.0.1:8080",
		},
		UseForwardedHeaders:           true,
		CodeChallengeMethodsSupported: []string{"some_random_value"},
	}

	oidcCfg := forwardedDiscovery(t, m, "https", "mockoidc.example.com")

	assert.Equal(t, "https://mockoidc.example.com/oidc", oidcCfg["issuer"])
	assert.Equal(t, "https://mockoidc.example.com/oidc/authorize", oidcCfg["authorization_endpoint"])
	assert.Equal(t, "https://mockoidc.example.com/oidc/token", oidcCfg["token_endpoint"])
	assert.Equal(t, "https://mockoidc.example.com/oidc/userinfo", oidcCfg["userinfo_endpoint"])
	assert.Equal(t, "https://mockoidc.example.com/oidc/.well-known/jwks.json", oidcCfg["jwks_uri"])
	assert.Equal(t, "https://mockoidc.example.com/oidc/endsession", oidcCfg["end_session_endpoint"])
}

func TestMockOIDC_Discovery_ForwardedHeaders_MultipleProxies(t *testing.T) {
	m := &mockoidc.MockOIDC{
		Server: &http.Server{
			Addr: "127.0.0.1:8080",
		},
		UseForwardedHeaders: true,
	}

	// A chain of proxies appends its own values. The first value is the
	// one that applies to the client.
	oidcCfg := forwardedDiscovery(t, m, "https, http", "mockoidc.example.com, internal.service:8080")

	assert.Equal(t, "https://mockoidc.example.com/oidc", oidcCfg["issuer"])
	assert.Equal(t, "https://mockoidc.example.com/oidc/token", oidcCfg["token_endpoint"])
	assert.Equal(t, "https://mockoidc.example.com/oidc/endsession", oidcCfg["end_session_endpoint"])
}

func TestMockOIDC_Discovery_ForwardedHeaders_Disabled(t *testing.T) {
	m := &mockoidc.MockOIDC{
		Server: &http.Server{
			Addr: "127.0.0.1:8080",
		},
	}

	oidcCfg := forwardedDiscovery(t, m, "https", "mockoidc.example.com")

	// Without the opt-in, forwarded headers are ignored
	assert.Equal(t, "http://127.0.0.1:8080/oidc", oidcCfg["issuer"])
	assert.Equal(t, "http://127.0.0.1:8080/oidc/token", oidcCfg["token_endpoint"])
	assert.Equal(t, "http://127.0.0.1:8080/oidc/endsession", oidcCfg["end_session_endpoint"])
}

func TestMockOIDC_Discovery_ForwardedHeaders_HostHeaderFallback(t *testing.T) {
	m := &mockoidc.MockOIDC{
		Server: &http.Server{
			Addr: "127.0.0.1:8080",
		},
		UseForwardedHeaders: true,
	}

	// A proxy that preserves the Host header doesn't need to set
	// X-Forwarded-Host.
	req := httptest.NewRequest(
		http.MethodGet, "http://mockoidc.example.com"+mockoidc.DiscoveryEndpoint, nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	recorder := httptest.NewRecorder()
	m.Discovery(recorder, req)

	oidcCfg := make(map[string]interface{})
	err := getJSON(recorder, &oidcCfg)
	assert.NoError(t, err)

	assert.Equal(t, "https://mockoidc.example.com/oidc", oidcCfg["issuer"])
	assert.Equal(t, "https://mockoidc.example.com/oidc/token", oidcCfg["token_endpoint"])
}

func TestMockOIDC_Token_ForwardedHeaders(t *testing.T) {
	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)
	m.Server = &http.Server{Addr: "127.0.0.1:8080"}
	m.UseForwardedHeaders = true

	session, err := m.SessionStore.NewSession(
		"openid email profile", "nonce", mockoidc.DefaultUser(), "", "")
	assert.NoError(t, err)

	data := url.Values{}
	data.Set("client_id", m.ClientID)
	data.Set("client_secret", m.ClientSecret)
	data.Set("code", session.SessionID)
	data.Set("grant_type", "authorization_code")

	rr := httptest.NewRecorder()
	req, err := http.NewRequest(
		http.MethodPost, mockoidc.TokenEndpoint, strings.NewReader(data.Encode()))
	assert.NoError(t, err)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "mockoidc.example.com")
	m.Token(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	tokenResp := make(map[string]interface{})
	err = getJSON(rr, &tokenResp)
	assert.NoError(t, err)

	// All issued tokens carry the public issuer, matching what the
	// discovery document advertised behind the proxy.
	for _, key := range []string{"access_token", "id_token", "refresh_token"} {
		token, err := m.Keypair.VerifyJWT(tokenResp[key].(string), m.Now)
		assert.NoError(t, err)

		claims, ok := token.Claims.(jwt.MapClaims)
		assert.True(t, ok)
		assert.Equal(t, "https://mockoidc.example.com/oidc", claims["iss"])
	}
}

func forwardedDiscovery(t *testing.T, m *mockoidc.MockOIDC, proto, host string) map[string]interface{} {
	t.Helper()

	req := httptest.NewRequest(
		http.MethodGet, "http://internal.service:8080"+mockoidc.DiscoveryEndpoint, nil)
	if proto != "" {
		req.Header.Set("X-Forwarded-Proto", proto)
	}
	if host != "" {
		req.Header.Set("X-Forwarded-Host", host)
	}

	recorder := httptest.NewRecorder()
	m.Discovery(recorder, req)

	oidcCfg := make(map[string]interface{})
	err := getJSON(recorder, &oidcCfg)
	assert.NoError(t, err)
	return oidcCfg
}

func getJSON(res *httptest.ResponseRecorder, target interface{}) error {
	return json.NewDecoder(res.Body).Decode(target)
}

func testResponse(t *testing.T, endpoint string, handler http.HandlerFunc,
	method string, values url.Values) *httptest.ResponseRecorder {

	rr := httptest.NewRecorder()

	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(values.Encode())
	} else if len(values) > 0 {
		endpoint = endpoint + "?" + values.Encode()
	}

	req, err := http.NewRequest(method, endpoint, body)
	assert.NoError(t, err)

	if method == http.MethodPost {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Content-Length", strconv.Itoa(len(values.Encode())))
	}
	handler(rr, req)
	return rr
}
