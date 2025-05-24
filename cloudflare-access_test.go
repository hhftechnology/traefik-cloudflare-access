
package cloudflareaccess_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"           // This import was missing - needed for certificate operations
	"crypto/x509/pkix"      // This import was missing - needed for certificate subject info
	"encoding/base64"
	"encoding/json"
	"math/big"              // This import was missing - needed for certificate serial numbers
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hhftechnology/traefik-cloudflare-access"  // Make sure this matches your actual module name
)

func TestCloudflareAccessMissingToken(t *testing.T) {
	// Given
	cfg := cloudflareaccess.CreateConfig()
	cfg.TeamDomain = "https://test.cloudflareaccess.com"
	cfg.PolicyAUD = "test-audience"
	
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := cloudflareaccess.New(ctx, next, cfg, "cloudflare-access-plugin")
	if err != nil {
		t.Fatal(err)
	}
	
	recorder := httptest.NewRecorder()

	// When
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)

	// Then
	assertStatusCode(t, recorder.Result(), http.StatusUnauthorized)
	assertContentType(t, recorder.Result(), "text/html; charset=utf-8")
}

func TestCloudflareAccessValidTokenHeader(t *testing.T) {
	// Given
	audience := "test-audience"
	
	// Create test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	
	// Mock server for JWKS endpoint - create this FIRST
	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()
	
	// Use the mock server URL as the team domain (keep it as HTTP for testing)
	teamDomain := jwksServer.URL
	
	// Create JWT token with the mock server URL as issuer
	token, err := createTestJWT(teamDomain, audience, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	
	cfg := cloudflareaccess.CreateConfig()
	cfg.TeamDomain = teamDomain
	cfg.PolicyAUD = audience
	cfg.SkipClientIDCheck = false
	cfg.SkipExpiryCheck = true // Skip expiry for test simplicity
	
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := cloudflareaccess.New(ctx, next, cfg, "cloudflare-access-plugin")
	if err != nil {
		t.Fatal(err)
	}
	
	recorder := httptest.NewRecorder()

	// When
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cf-Access-Jwt-Assertion", token)
	handler.ServeHTTP(recorder, req)

	// Then
	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestCloudflareAccessValidTokenCookie(t *testing.T) {
	// Given
	audience := "test-audience"
	
	// Create test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	
	// Mock server for JWKS endpoint - create this FIRST
	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()
	
	// Use the mock server URL as the team domain (keep it as HTTP for testing)
	teamDomain := jwksServer.URL
	
	// Create JWT token with the mock server URL as issuer
	token, err := createTestJWT(teamDomain, audience, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	
	cfg := cloudflareaccess.CreateConfig()
	cfg.TeamDomain = teamDomain
	cfg.PolicyAUD = audience
	cfg.SkipClientIDCheck = false
	cfg.SkipExpiryCheck = true // Skip expiry for test simplicity
	
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := cloudflareaccess.New(ctx, next, cfg, "cloudflare-access-plugin")
	if err != nil {
		t.Fatal(err)
	}
	
	recorder := httptest.NewRecorder()

	// When
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{
		Name:  "CF_AUTHORIZATION",
		Value: token,
	})
	handler.ServeHTTP(recorder, req)

	// Then
	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestCloudflareAccessInvalidAudience(t *testing.T) {
	// Given
	teamDomain := "https://test.cloudflareaccess.com"
	audience := "test-audience"
	wrongAudience := "wrong-audience"
	
	// Create test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	
	// Create JWT token with wrong audience
	token, err := createTestJWT(teamDomain, wrongAudience, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	
	// Mock server for JWKS endpoint
	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()
	
	cfg := cloudflareaccess.CreateConfig()
	cfg.TeamDomain = strings.Replace(jwksServer.URL, "http://", "https://", 1)
	cfg.PolicyAUD = audience // Correct audience
	cfg.SkipClientIDCheck = false
	cfg.SkipExpiryCheck = true
	
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := cloudflareaccess.New(ctx, next, cfg, "cloudflare-access-plugin")
	if err != nil {
		t.Fatal(err)
	}
	
	recorder := httptest.NewRecorder()

	// When
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cf-Access-Jwt-Assertion", token)
	handler.ServeHTTP(recorder, req)

	// Then
	assertStatusCode(t, recorder.Result(), http.StatusUnauthorized)
}

func TestCloudflareAccessInvalidIssuer(t *testing.T) {
	// Given
	wrongIssuer := "https://wrong.cloudflareaccess.com"
	audience := "test-audience"
	
	// Create test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	
	// Create JWT token with wrong issuer
	token, err := createTestJWT(wrongIssuer, audience, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	
	// Mock server for JWKS endpoint
	jwksServer := createMockJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()
	
	cfg := cloudflareaccess.CreateConfig()
	cfg.TeamDomain = strings.Replace(jwksServer.URL, "http://", "https://", 1)
	cfg.PolicyAUD = audience
	cfg.SkipClientIDCheck = false
	cfg.SkipExpiryCheck = true
	
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := cloudflareaccess.New(ctx, next, cfg, "cloudflare-access-plugin")
	if err != nil {
		t.Fatal(err)
	}
	
	recorder := httptest.NewRecorder()

	// When
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cf-Access-Jwt-Assertion", token)
	handler.ServeHTTP(recorder, req)

	// Then
	assertStatusCode(t, recorder.Result(), http.StatusUnauthorized)
}

func TestCloudflareAccessConfigValidation(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	// Test missing team domain
	cfg1 := cloudflareaccess.CreateConfig()
	cfg1.PolicyAUD = "test-audience"
	_, err := cloudflareaccess.New(ctx, next, cfg1, "test")
	if err == nil {
		t.Error("Expected error for missing team domain")
	}

	// Test missing policy AUD
	cfg2 := cloudflareaccess.CreateConfig()
	cfg2.TeamDomain = "https://test.cloudflareaccess.com"
	_, err = cloudflareaccess.New(ctx, next, cfg2, "test")
	if err == nil {
		t.Error("Expected error for missing policy AUD")
	}
}

func TestCloudflareAccessCustomBlockPage(t *testing.T) {
	// Given
	cfg := cloudflareaccess.CreateConfig()
	cfg.TeamDomain = "https://test.cloudflareaccess.com"
	cfg.PolicyAUD = "test-audience"
	cfg.BlockPageTitle = "Custom Access Denied"
	cfg.BlockPageMessage = "Custom message for unauthorized access"
	
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := cloudflareaccess.New(ctx, next, cfg, "cloudflare-access-plugin")
	if err != nil {
		t.Fatal(err)
	}
	
	recorder := httptest.NewRecorder()

	// When
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)

	// Then
	assertStatusCode(t, recorder.Result(), http.StatusUnauthorized)
	body := recorder.Body.String()
	if !strings.Contains(body, "Custom Access Denied") {
		t.Error("Expected custom block page title")
	}
	if !strings.Contains(body, "Custom message for unauthorized access") {
		t.Error("Expected custom block page message")
	}
}

// Helper functions

func assertStatusCode(t *testing.T, resp *http.Response, expected int) {
	t.Helper()
	if resp.StatusCode != expected {
		t.Errorf("Expected status code %d, got %d", expected, resp.StatusCode)
	}
}

func assertContentType(t *testing.T, resp *http.Response, expected string) {
	t.Helper()
	contentType := resp.Header.Get("Content-Type")
	if contentType != expected {
		t.Errorf("Expected content type %s, got %s", expected, contentType)
	}
}

func createTestJWT(issuer, audience string, privateKey *rsa.PrivateKey) (string, error) {
	// Create header
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "test-key-id",
	}
	
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	
	// Create claims
	now := time.Now()
	claims := map[string]interface{}{
		"iss":   issuer,
		"aud":   audience,
		"sub":   "test-user",
		"email": "test@example.com",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"nbf":   now.Unix(),
	}
	
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	
	// Encode header and claims
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsBytes)
	
	// Create signature
	signingString := headerEncoded + "." + claimsEncoded
	
	hasher := sha256.New()
	hasher.Write([]byte(signingString))
	hash := hasher.Sum(nil)
	
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash)
	if err != nil {
		return "", err
	}
	
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)
	
	return signingString + "." + signatureEncoded, nil
}

func createMockCertificate(publicKey *rsa.PublicKey) (*x509.Certificate, error) {
	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Organization"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  nil,
	}

	// Create a temporary private key for signing the certificate
	// In a real scenario, this would be a CA's private key
	tempPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, tempPrivKey)
	if err != nil {
		return nil, err
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func createMockJWKSServer(t *testing.T, publicKey *rsa.PublicKey) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/cdn-cgi/access/certs") {
			http.NotFound(w, r)
			return
		}
		
		// Create a proper mock X.509 certificate for testing
		cert, err := createMockCertificate(publicKey)
		if err != nil {
			t.Fatalf("Failed to create mock certificate: %v", err)
		}
		
		certB64 := base64.StdEncoding.EncodeToString(cert.Raw)
		
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"alg": "RS256",
					"kid": "test-key-id",
					"kty": "RSA",
					"use": "sig",
					"x5c": []string{certB64},
					"n": base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
					"e": "AQAB", // 65537 in base64
				},
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
}