// Package cloudflareaccess provides Cloudflare Access authentication middleware for Traefik.
package traefik_cloudflare_access

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Config holds the plugin configuration.
type Config struct {
	// TeamDomain is your Cloudflare Access team domain (e.g., "https://myteam.cloudflareaccess.com")
	TeamDomain string `json:"teamDomain,omitempty"`
	
	// PolicyAUD is the Application Audience (AUD) tag for your application
	PolicyAUD string `json:"policyAUD,omitempty"`
	
	// SkipClientIDCheck skips the client ID verification (default: false)
	SkipClientIDCheck bool `json:"skipClientIDCheck,omitempty"`
	
	// SkipExpiryCheck skips the token expiry verification (default: false)
	SkipExpiryCheck bool `json:"skipExpiryCheck,omitempty"`
	
	// BlockPageTitle is the title shown on the block page (default: "Access Denied")
	BlockPageTitle string `json:"blockPageTitle,omitempty"`
	
	// BlockPageMessage is the message shown on the block page
	BlockPageMessage string `json:"blockPageMessage,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TeamDomain:        "",
		PolicyAUD:         "",
		SkipClientIDCheck: false,
		SkipExpiryCheck:   false,
		BlockPageTitle:    "Access Denied",
		BlockPageMessage:  "You don't have permission to access this resource. Please authenticate through Cloudflare Access.",
	}
}

// CloudflareAccess is the plugin struct that implements the middleware.
type CloudflareAccess struct {
	next   http.Handler
	name   string
	config *Config
	client *http.Client
}

// JWTHeader represents the JWT header structure.
type JWTHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

// JWTClaims represents the JWT claims structure.
type JWTClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Email     string `json:"email,omitempty"`
}

// CloudflareKey represents a public key from Cloudflare's JWKS endpoint.
type CloudflareKey struct {
	Algorithm string   `json:"alg"`
	KeyID     string   `json:"kid"`
	KeyType   string   `json:"kty"`
	Use       string   `json:"use"`
	X5C       []string `json:"x5c"`
	N         string   `json:"n"`
	E         string   `json:"e"`
}

// CloudflareKeySet represents the response from Cloudflare's JWKS endpoint.
type CloudflareKeySet struct {
	Keys []CloudflareKey `json:"keys"`
}

// New creates a new CloudflareAccess plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Validate required configuration
	if config.TeamDomain == "" {
		return nil, fmt.Errorf("teamDomain is required")
	}
	
	if config.PolicyAUD == "" {
		return nil, fmt.Errorf("policyAUD is required")
	}
	
	// Ensure team domain has proper format
	if !strings.HasPrefix(config.TeamDomain, "https://") {
		config.TeamDomain = "https://" + config.TeamDomain
	}
	
	if !strings.HasSuffix(config.TeamDomain, ".cloudflareaccess.com") && !strings.Contains(config.TeamDomain, ".cloudflareaccess.com") {
		config.TeamDomain = config.TeamDomain + ".cloudflareaccess.com"
	}

	return &CloudflareAccess{
		next:   next,
		name:   name,
		config: config,
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// ServeHTTP implements the http.Handler interface.
func (ca *CloudflareAccess) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Extract JWT token from header or cookie
	accessJWT := ca.extractToken(req)
	if accessJWT == "" {
		ca.renderBlockPage(rw, "No authentication token found")
		return
	}

	// Verify the JWT token
	if err := ca.verifyToken(req.Context(), accessJWT); err != nil {
		ca.renderBlockPage(rw, fmt.Sprintf("Authentication failed: %s", err.Error()))
		return
	}

	// Token is valid, proceed to next handler
	ca.next.ServeHTTP(rw, req)
}

// extractToken extracts the JWT token from the request header or cookie.
func (ca *CloudflareAccess) extractToken(req *http.Request) string {
	// First, try to get token from header
	accessJWT := req.Header.Get("Cf-Access-Jwt-Assertion")
	if accessJWT != "" {
		return accessJWT
	}

	// If not in header, try to get from cookie
	cookie, err := req.Cookie("CF_AUTHORIZATION")
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	return ""
}

// verifyToken verifies the JWT token against Cloudflare's public keys.
func (ca *CloudflareAccess) verifyToken(ctx context.Context, token string) error {
	// Parse JWT token
	header, claims, signature, err := ca.parseJWT(token)
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Verify claims
	if err := ca.verifyClaims(claims); err != nil {
		return fmt.Errorf("invalid claims: %w", err)
	}

	// Get public key from Cloudflare
	publicKey, err := ca.getPublicKey(ctx, header.KeyID)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	// Verify signature
	if err := ca.verifySignature(token, signature, publicKey); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	return nil
}

// parseJWT parses a JWT token and returns its components.
func (ca *CloudflareAccess) parseJWT(token string) (*JWTHeader, *JWTClaims, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("invalid JWT format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	return &header, &claims, signature, nil
}

// verifyClaims verifies the JWT claims.
func (ca *CloudflareAccess) verifyClaims(claims *JWTClaims) error {
	// Verify issuer
	if claims.Issuer != ca.config.TeamDomain {
		return fmt.Errorf("invalid issuer: expected %s, got %s", ca.config.TeamDomain, claims.Issuer)
	}

	// Verify audience unless skipped
	if !ca.config.SkipClientIDCheck && claims.Audience != ca.config.PolicyAUD {
		return fmt.Errorf("invalid audience: expected %s, got %s", ca.config.PolicyAUD, claims.Audience)
	}

	// Verify expiry unless skipped
	if !ca.config.SkipExpiryCheck {
		now := time.Now().Unix()
		if claims.ExpiresAt != 0 && now > claims.ExpiresAt {
			return fmt.Errorf("token has expired")
		}
		if claims.NotBefore != 0 && now < claims.NotBefore {
			return fmt.Errorf("token not valid yet")
		}
	}

	return nil
}

// getPublicKey retrieves the public key from Cloudflare's JWKS endpoint.
func (ca *CloudflareAccess) getPublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", ca.config.TeamDomain)
	
	req, err := http.NewRequestWithContext(ctx, "GET", certsURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := ca.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch certificates: status %d", resp.StatusCode)
	}

	var keySet CloudflareKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keySet); err != nil {
		return nil, err
	}

	// Find the key with matching key ID
	for _, key := range keySet.Keys {
		if key.KeyID == keyID {
			return ca.parsePublicKey(&key)
		}
	}

	return nil, fmt.Errorf("public key not found for key ID: %s", keyID)
}

// parsePublicKey converts a Cloudflare key to an RSA public key.
func (ca *CloudflareAccess) parsePublicKey(key *CloudflareKey) (*rsa.PublicKey, error) {
	if len(key.X5C) == 0 {
		return nil, fmt.Errorf("no x5c certificate found")
	}

	// Decode the certificate
	certBytes, err := base64.StdEncoding.DecodeString(key.X5C[0])
	if err != nil {
		return nil, err
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	// Extract the public key
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain RSA public key")
	}

	return publicKey, nil
}

// verifySignature verifies the JWT signature using the public key.
func (ca *CloudflareAccess) verifySignature(token string, signature []byte, publicKey *rsa.PublicKey) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Create the signed content (header + "." + payload)
	signedContent := parts[0] + "." + parts[1]
	
	// Hash the content
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(signedContent))
	hash := hasher.Sum(nil)

	// Verify signature using PKCS1v15
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash, signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// renderBlockPage renders an HTML block page for unauthorized access.
func (ca *CloudflareAccess) renderBlockPage(rw http.ResponseWriter, reason string) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusUnauthorized)

	blockPageHTML := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: white;
            border-radius: 10px;
            padding: 40px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 500px;
            margin: 20px;
        }
        .icon {
            font-size: 64px;
            color: #e74c3c;
            margin-bottom: 20px;
        }
        h1 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 28px;
        }
        p {
            color: #7f8c8d;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .reason {
            background: #f8f9fa;
            border-left: 4px solid #e74c3c;
            padding: 15px;
            margin: 20px 0;
            text-align: left;
            font-family: monospace;
            font-size: 14px;
            color: #2c3e50;
        }
        .footer {
            margin-top: 30px;
            color: #95a5a6;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🚫</div>
        <h1>%s</h1>
        <p>%s</p>
        <div class="reason">%s</div>
        <div class="footer">
            Protected by Cloudflare Access
        </div>
    </div>
</body>
</html>`, ca.config.BlockPageTitle, ca.config.BlockPageTitle, ca.config.BlockPageMessage, reason)

	rw.Write([]byte(blockPageHTML))
}