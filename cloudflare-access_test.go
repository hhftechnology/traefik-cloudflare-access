package traefik_cloudflare_access_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hhftechnology/traefik-cloudflare-access"
)

// Test 1: Basic functionality - missing token should return 401
func TestCloudflareAccessMissingToken(t *testing.T) {
	// Given: A properly configured plugin
	cfg := traefik_cloudflare_access.CreateConfig()
	cfg.TeamDomain = "https://test.cloudflareaccess.com"
	cfg.PolicyAUD = "test-audience"
	
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// This should never be called since there's no token
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("success"))
	})

	handler, err := traefik_cloudflare_access.New(ctx, next, cfg, "cloudflare-access-plugin")
	if err != nil {
		t.Fatal(err)
	}
	
	recorder := httptest.NewRecorder()

	// When: Making a request without any authentication token
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)

	// Then: Should get 401 Unauthorized with HTML block page
	assertStatusCode(t, recorder.Result(), http.StatusUnauthorized)
	assertContentType(t, recorder.Result(), "text/html; charset=utf-8")
	
	// Verify block page contains expected content
	body := recorder.Body.String()
	if !strings.Contains(body, "Access Denied") {
		t.Error("Expected block page to contain 'Access Denied'")
	}
}

// Test 2: Token extraction from header
func TestCloudflareAccessTokenExtractionFromHeader(t *testing.T) {
	// Given: A plugin that skips actual JWT verification for testing
	cfg := traefik_cloudflare_access.CreateConfig()
	cfg.TeamDomain = "https://test.cloudflareaccess.com"
	cfg.PolicyAUD = "test-audience"
	cfg.SkipClientIDCheck = true
	cfg.SkipExpiryCheck = true
	
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("success"))
	})

	handler, err := traefik_cloudflare_access.New(ctx, next, cfg, "cloudflare-access-plugin")
	if err != nil {
		t.Fatal(err)
	}
	
	recorder := httptest.NewRecorder()

	// When: Making a request with a token in the header
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Add a dummy token - we're not testing JWT validation here, just token extraction
	req.Header.Set("Cf-Access-Jwt-Assertion", "dummy.token.here")
	handler.ServeHTTP(recorder, req)

	// Then: Should attempt to process the token (may fail JWT validation, but that's expected)
	// The key test is that it found the token and didn't immediately return 401 for "no token"
	response := recorder.Result()
	body := recorder.Body.String()
	
	// If it returns 401, it should be due to JWT validation failure, not missing token
	if response.StatusCode == http.StatusUnauthorized {
		if strings.Contains(body, "No authentication token found") {
			t.Error("Token extraction failed - plugin didn't find the token in the header")
		}
		// JWT validation failure is expected with dummy token
	}
}

// Test 3: Token extraction from cookie
func TestCloudflareAccessTokenExtractionFromCookie(t *testing.T) {
	// Given: A plugin that skips actual JWT verification for testing
	cfg := traefik_cloudflare_access.CreateConfig()
	cfg.TeamDomain = "https://test.cloudflareaccess.com"
	cfg.PolicyAUD = "test-audience"
	cfg.SkipClientIDCheck = true
	cfg.SkipExpiryCheck = true
	
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("success"))
	})

	handler, err := traefik_cloudflare_access.New(ctx, next, cfg, "cloudflare-access-plugin")
	if err != nil {
		t.Fatal(err)
	}
	
	recorder := httptest.NewRecorder()

	// When: Making a request with a token in a cookie
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Add a dummy token in cookie format
	req.AddCookie(&http.Cookie{
		Name:  "CF_AUTHORIZATION",
		Value: "dummy.token.here",
	})
	handler.ServeHTTP(recorder, req)

	// Then: Should attempt to process the token
	response := recorder.Result()
	body := recorder.Body.String()
	
	// If it returns 401, it should be due to JWT validation failure, not missing token
	if response.StatusCode == http.StatusUnauthorized {
		if strings.Contains(body, "No authentication token found") {
			t.Error("Token extraction failed - plugin didn't find the token in the cookie")
		}
		// JWT validation failure is expected with dummy token
	}
}

// Test 4: Configuration validation
func TestCloudflareAccessConfigValidation(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	// Test missing team domain
	cfg1 := traefik_cloudflare_access.CreateConfig()
	cfg1.PolicyAUD = "test-audience"
	_, err := traefik_cloudflare_access.New(ctx, next, cfg1, "test")
	if err == nil {
		t.Error("Expected error for missing team domain")
	}

	// Test missing policy AUD
	cfg2 := traefik_cloudflare_access.CreateConfig()
	cfg2.TeamDomain = "https://test.cloudflareaccess.com"
	_, err = traefik_cloudflare_access.New(ctx, next, cfg2, "test")
	if err == nil {
		t.Error("Expected error for missing policy AUD")
	}

	// Test valid configuration
	cfg3 := traefik_cloudflare_access.CreateConfig()
	cfg3.TeamDomain = "https://test.cloudflareaccess.com"
	cfg3.PolicyAUD = "test-audience"
	_, err = traefik_cloudflare_access.New(ctx, next, cfg3, "test")
	if err != nil {
		t.Errorf("Expected no error for valid configuration, got: %v", err)
	}
}

// Test 5: Custom block page content
func TestCloudflareAccessCustomBlockPage(t *testing.T) {
	// Given: A plugin with custom block page configuration
	cfg := traefik_cloudflare_access.CreateConfig()
	cfg.TeamDomain = "https://test.cloudflareaccess.com"
	cfg.PolicyAUD = "test-audience"
	cfg.BlockPageTitle = "Custom Access Denied"
	cfg.BlockPageMessage = "Custom message for unauthorized access"
	
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := traefik_cloudflare_access.New(ctx, next, cfg, "cloudflare-access-plugin")
	if err != nil {
		t.Fatal(err)
	}
	
	recorder := httptest.NewRecorder()

	// When: Making a request without authentication
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)

	// Then: Block page should contain custom content
	assertStatusCode(t, recorder.Result(), http.StatusUnauthorized)
	body := recorder.Body.String()
	if !strings.Contains(body, "Custom Access Denied") {
		t.Error("Expected custom block page title")
	}
	if !strings.Contains(body, "Custom message for unauthorized access") {
		t.Error("Expected custom block page message")
	}
}

// Test 6: Team domain normalization
func TestCloudflareAccessTeamDomainNormalization(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	// Test domain without https:// prefix gets normalized
	cfg1 := traefik_cloudflare_access.CreateConfig()
	cfg1.TeamDomain = "myteam.cloudflareaccess.com"
	cfg1.PolicyAUD = "test-audience"
	
	handler1, err := traefik_cloudflare_access.New(ctx, next, cfg1, "test")
	if err != nil {
		t.Fatal(err)
	}
	
	// Verify the handler was created successfully (domain was normalized)
	if handler1 == nil {
		t.Error("Handler should be created successfully with normalized domain")
	}

	// Test domain without .cloudflareaccess.com suffix gets normalized
	cfg2 := traefik_cloudflare_access.CreateConfig()
	cfg2.TeamDomain = "https://myteam"
	cfg2.PolicyAUD = "test-audience"
	
	handler2, err := traefik_cloudflare_access.New(ctx, next, cfg2, "test")
	if err != nil {
		t.Fatal(err)
	}
	
	// Verify the handler was created successfully (domain was normalized)
	if handler2 == nil {
		t.Error("Handler should be created successfully with normalized domain")
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