package mockoidc

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// NowFunc is an overrideable version of `time.Now`. Tests that need to
// manipulate time can use their own `func() Time` function.
var NowFunc = time.Now

// MockOIDC is a minimal OIDC server for use in OIDC authentication
// integration testing.
type MockOIDC struct {
	ClientID     string
	ClientSecret string

	// Host overrides the host used to build endpoint URLs. Set it to a
	// hostname (e.g. "mockoidc.example.com") or a full URL
	// (e.g. "https://mockoidc.example.com") when running behind a proxy
	// that terminates TLS.
	Host string

	// UseForwardedHeaders derives the scheme and host of URLs emitted while
	// handling requests from the X-Forwarded-Proto and X-Forwarded-Host
	// headers (falling back to the Host header), instead of the statically
	// configured address. Enable this when running behind a reverse proxy
	// or load balancer that terminates TLS.
	UseForwardedHeaders bool

	AccessTTL  time.Duration
	RefreshTTL time.Duration

	CodeChallengeMethodsSupported []string

	// Normally, these would be private. Expose them publicly for
	// power users.
	Server       *http.Server
	Keypair      *Keypair
	SessionStore *SessionStore
	UserQueue    *UserQueue
	ErrorQueue   *ErrorQueue

	tlsConfig   *tls.Config
	middleware  []func(http.Handler) http.Handler
	fastForward time.Duration
}

// Config gives the various settings MockOIDC starts with that a test
// application server would need to be configured with.
type Config struct {
	ClientID     string
	ClientSecret string
	Issuer       string

	AccessTTL  time.Duration
	RefreshTTL time.Duration

	CodeChallengeMethodsSupported []string
}

// NewServer configures a new MockOIDC that isn't started. An existing
// rsa.PrivateKey can be passed for token signing operations in case
// the default Keypair isn't desired.
func NewServer(key *rsa.PrivateKey) (*MockOIDC, error) {
	clientID, err := randomNonce(24)
	if err != nil {
		return nil, err
	}
	clientSecret, err := randomNonce(24)
	if err != nil {
		return nil, err
	}
	keypair, err := NewKeypair(key)
	if err != nil {
		return nil, err
	}

	return &MockOIDC{
		ClientID:                      clientID,
		ClientSecret:                  clientSecret,
		AccessTTL:                     time.Duration(10) * time.Minute,
		RefreshTTL:                    time.Duration(60) * time.Minute,
		CodeChallengeMethodsSupported: []string{"plain", "S256"},
		Keypair:                       keypair,
		SessionStore:                  NewSessionStore(),
		UserQueue:                     &UserQueue{},
		ErrorQueue:                    &ErrorQueue{},
	}, nil
}

// Run creates a default MockOIDC server and starts it
func Run() (*MockOIDC, error) {
	return RunTLS(nil)
}

// RunTLS creates a default MockOIDC server and starts it. It takes a
// tester configured tls.Config for TLS support.
func RunTLS(cfg *tls.Config) (*MockOIDC, error) {
	m, err := NewServer(nil)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return m, m.Start(ln, cfg)
}

// Start starts the MockOIDC server in its own Goroutine on the provided
// net.Listener. In generic `Run`, this defaults to `127.0.0.1:0`
func (m *MockOIDC) Start(ln net.Listener, cfg *tls.Config) error {
	if m.Server != nil {
		return errors.New("server already started")
	}

	handler := http.NewServeMux()
	handler.Handle(AuthorizationEndpoint, m.chainMiddleware(m.Authorize))
	handler.Handle(TokenEndpoint, m.chainMiddleware(m.Token))
	handler.Handle(UserinfoEndpoint, m.chainMiddleware(m.Userinfo))
	handler.Handle(JWKSEndpoint, m.chainMiddleware(m.JWKS))
	handler.Handle(DiscoveryEndpoint, m.chainMiddleware(m.Discovery))
	handler.Handle(LogoutEndpoint, m.chainMiddleware(m.Logout))
	handler.Handle(EndSessionEndpoint, m.chainMiddleware(m.Logout))

	m.Server = &http.Server{
		Addr:      ln.Addr().String(),
		Handler:   handler,
		TLSConfig: cfg,
	}
	// Track this to know if we are https
	m.tlsConfig = cfg

	go func() {
		err := m.Server.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	return nil
}

// Shutdown stops the MockOIDC server. Use this to cleanup test runs.
func (m *MockOIDC) Shutdown() error {
	return m.Server.Shutdown(context.Background())
}

func (m *MockOIDC) AddMiddleware(mw func(http.Handler) http.Handler) error {
	if m.Server != nil {
		return errors.New("server already started")
	}

	m.middleware = append(m.middleware, mw)
	return nil
}

// Config returns the Config with options a connection application or unit
// tests need to be aware of.
func (m *MockOIDC) Config() *Config {
	return &Config{
		ClientID:                      m.ClientID,
		ClientSecret:                  m.ClientSecret,
		Issuer:                        m.Issuer(),
		CodeChallengeMethodsSupported: m.CodeChallengeMethodsSupported,
		AccessTTL:                     m.AccessTTL,
		RefreshTTL:                    m.RefreshTTL,
	}
}

// QueueUser allows adding mock User objects to the authentication queue.
// Calls to the `authorization_endpoint` will pop these mock User objects
// off the queue and create a session with them.
func (m *MockOIDC) QueueUser(user User) {
	m.UserQueue.Push(user)
}

// QueueCode allows adding mock code strings to the authentication queue.
// Calls to the `authorization_endpoint` will pop these code strings
// off the queue and create a session with them and return them as the
// code parameter in the response.
func (m *MockOIDC) QueueCode(code string) {
	m.SessionStore.CodeQueue.Push(code)
}

// QueueError allows queueing arbitrary errors for the next handler calls
// to return.
func (m *MockOIDC) QueueError(se *ServerError) {
	m.ErrorQueue.Push(se)
}

// FastForward moves the MockOIDC's internal view of time forward.
// Use this to test token expirations in your tests.
func (m *MockOIDC) FastForward(d time.Duration) time.Duration {
	m.fastForward = m.fastForward + d
	return m.fastForward
}

// Now is what MockOIDC thinks time.Now is
func (m *MockOIDC) Now() time.Time {
	return NowFunc().Add(m.fastForward)
}

// Addr returns the server address (if started). A Host set to a full URL
// (e.g. "https://mockoidc.example.com") is returned as-is, otherwise the
// scheme is inferred from the configured TLS config.
func (m *MockOIDC) Addr() string {
	if m.Server == nil {
		return ""
	}
	if strings.HasPrefix(m.Host, "http://") || strings.HasPrefix(m.Host, "https://") {
		return strings.TrimSuffix(m.Host, "/")
	}
	proto := "http"
	if m.tlsConfig != nil {
		proto = "https"
	}
	if m.Host != "" {
		return fmt.Sprintf("%s://%s", proto, m.Host)
	}
	return fmt.Sprintf("%s://%s", proto, m.Server.Addr)
}

// baseURL returns the scheme://host base to use for URLs emitted while
// handling req. When UseForwardedHeaders is enabled, the X-Forwarded-Proto
// and X-Forwarded-Host headers are honored (falling back to the Host header)
// so MockOIDC can run behind a proxy that terminates TLS. Otherwise the
// statically configured address is returned.
func (m *MockOIDC) baseURL(req *http.Request) string {
	if m.Server == nil {
		return ""
	}
	if !m.UseForwardedHeaders || req == nil {
		return m.Addr()
	}

	proto := strings.ToLower(firstHeaderValue(req.Header.Get("X-Forwarded-Proto")))
	if proto != "http" && proto != "https" {
		proto = ""
	}
	if proto == "" {
		if req.TLS != nil || m.tlsConfig != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}

	host := firstHeaderValue(req.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = req.Host
	}
	if host == "" {
		return m.Addr()
	}

	return fmt.Sprintf("%s://%s", proto, host)
}

// endpointURL builds a full endpoint URL for the passed request using the
// request-aware base URL. It returns an empty string if MockOIDC isn't
// started.
func (m *MockOIDC) endpointURL(req *http.Request, endpoint string) string {
	if base := m.baseURL(req); base != "" {
		return base + endpoint
	}
	return ""
}

// firstHeaderValue returns the first value of a comma-separated forwarded
// header, which is the value set by the proxy closest to the client.
func firstHeaderValue(value string) string {
	if value == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(value, ",")[0])
}

// Issuer returns the OIDC Issuer that will be in `iss` token claims
func (m *MockOIDC) Issuer() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + IssuerBase
}

// DiscoveryEndpoint returns the full `/.well-known/openid-configuration` URL
func (m *MockOIDC) DiscoveryEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + DiscoveryEndpoint
}

// AuthorizationEndpoint returns the OIDC `authorization_endpoint`
func (m *MockOIDC) AuthorizationEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + AuthorizationEndpoint
}

// TokenEndpoint returns the OIDC `token_endpoint`
func (m *MockOIDC) TokenEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + TokenEndpoint
}

// UserinfoEndpoint returns the OIDC `userinfo_endpoint`
func (m *MockOIDC) UserinfoEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + UserinfoEndpoint
}

// LogoutEndpoint returns the OIDC `logout_endpoint`
func (m *MockOIDC) LogoutEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + LogoutEndpoint
}

// EndSessionEndpoint returns the OIDC `end_session_endpoint`
func (m *MockOIDC) EndSessionEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + EndSessionEndpoint
}

// JWKSEndpoint returns the OIDC `jwks_uri`
func (m *MockOIDC) JWKSEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + JWKSEndpoint
}

func (m *MockOIDC) chainMiddleware(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	chain := m.forceError(http.HandlerFunc(endpoint))
	for i := len(m.middleware) - 1; i >= 0; i-- {
		mw := m.middleware[i]
		chain = mw(chain)
	}
	return chain
}

func (m *MockOIDC) forceError(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if se := m.ErrorQueue.Pop(); se != nil {
			errorResponse(rw, se.Error, se.Description, se.Code)
		} else {
			next.ServeHTTP(rw, req)
		}
	})
}
