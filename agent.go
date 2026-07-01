package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// The module holds no vault session of its own: it proxies to the local
// `privasys vault serve` agent, which owns the RA-TLS holder-of-key session to
// the constellation. Default matches `vault serve`'s default listen address.
func agentBase() string {
	if v := os.Getenv("PRIVASYS_PKCS11_AGENT"); v != "" {
		return v
	}
	return "http://127.0.0.1:8200"
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

// agentKey is one key as the agent's GET /keys lists it. `vault serve` reports
// keyType ("P256SigningKey"/"Aes256GcmKey"); a JOSE-shaped agent may report kty
// ("EC"/"oct") instead — accept both.
type agentKey struct {
	Name    string `json:"name"`
	KeyType string `json:"keyType"`
	Kty     string `json:"kty"`
}

// kind coarsely classifies the key: "EC" (P-256 signing) or "AES" (256-GCM).
func (k agentKey) kind() string {
	switch {
	case k.KeyType == "P256SigningKey" || k.Kty == "EC":
		return "EC"
	case k.KeyType == "Aes256GcmKey" || k.Kty == "oct" || k.Kty == "AES":
		return "AES"
	}
	return ""
}

func agentListKeys() ([]agentKey, error) {
	resp, err := httpClient.Get(agentBase() + "/keys")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent /keys: HTTP %d: %s", resp.StatusCode, string(body))
	}
	// The facade returns either a bare array or {"keys":[...]}; accept both.
	var arr []agentKey
	if json.Unmarshal(body, &arr) == nil && len(arr) > 0 {
		return arr, nil
	}
	var wrapped struct {
		Keys  []agentKey `json:"keys"`
		Value []agentKey `json:"value"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, fmt.Errorf("agent /keys: decode: %w", err)
	}
	if wrapped.Keys != nil {
		return wrapped.Keys, nil
	}
	return wrapped.Value, nil
}

// agentPublicEC fetches the named signing key's public JWK (agent GET
// /keys/{name}) and returns the uncompressed SEC1 point 0x04||X||Y (65 bytes
// for P-256). Backs CKA_EC_POINT, which OpenSSL's pkcs11-provider needs to
// build the EVP_PKEY public half for certs and TLS.
func agentPublicEC(name string) ([]byte, error) {
	resp, err := httpClient.Get(agentBase() + "/keys/" + url.PathEscape(name))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent public: HTTP %d: %s", resp.StatusCode, string(body))
	}
	// `vault serve` nests the JWK under "key"; a bare JWK is accepted too.
	type ecJWK struct {
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	var wrapped struct {
		Key ecJWK `json:"key"`
	}
	var jwk ecJWK
	if err := json.Unmarshal(body, &wrapped); err == nil && wrapped.Key.X != "" {
		jwk = wrapped.Key
	} else if err := json.Unmarshal(body, &jwk); err != nil || jwk.X == "" || jwk.Y == "" {
		return nil, fmt.Errorf("agent public: bad JWK: %s", string(body))
	}
	x, err := b64any(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("agent public: decode x: %w", err)
	}
	y, err := b64any(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("agent public: decode y: %w", err)
	}
	point := make([]byte, 0, 65)
	point = append(point, 0x04)
	point = append(point, leftPad32(x)...)
	point = append(point, leftPad32(y)...)
	return point, nil
}

// leftPad32 left-pads a big-endian coordinate to 32 bytes (JWK base64url drops
// leading zeros).
func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// agentSign asks the agent to sign msg with the named key. alg is a JOSE alg
// (ES256). When prehashed is set, msg is a 32-byte SHA-256 digest the vault signs
// raw (CKM_ECDSA); otherwise msg is the message the vault hashes (CKM_ECDSA_SHA256).
// The returned signature is raw r||s (64 bytes for P-256), which is exactly what
// PKCS#11 CKM_ECDSA* expects — no DER re-encoding.
func agentSign(name, alg string, msg []byte, prehashed bool) ([]byte, error) {
	reqBody, _ := json.Marshal(map[string]any{
		"alg":       alg,
		"value":     base64.RawURLEncoding.EncodeToString(msg),
		"prehashed": prehashed,
	})
	u := agentBase() + "/keys/" + url.PathEscape(name) + "/sign"
	resp, err := httpClient.Post(u, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent sign: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Value == "" {
		return nil, fmt.Errorf("agent sign: bad response: %s", string(body))
	}
	sig, err := b64any(out.Value)
	if err != nil {
		return nil, fmt.Errorf("agent sign: decode signature: %w", err)
	}
	return sig, nil
}

// agentWrap encrypts pt under the named AES key in the vault with the
// caller-supplied GCM iv (PKCS#11 CKM_AES_GCM fixes the nonce caller-side).
// Returns ciphertext||tag. Backs C_Encrypt(CKM_AES_GCM).
func agentWrap(name string, pt, iv []byte) ([]byte, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"value": base64.RawURLEncoding.EncodeToString(pt),
		"iv":    base64.RawURLEncoding.EncodeToString(iv),
	})
	u := agentBase() + "/keys/" + url.PathEscape(name) + "/wrapKey"
	resp, err := httpClient.Post(u, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent wrap: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Value == "" {
		return nil, fmt.Errorf("agent wrap: bad response: %s", string(body))
	}
	return b64any(out.Value)
}

// agentUnwrap decrypts ct (with the caller-supplied GCM iv) under the named AES
// key in the vault. Backs C_Decrypt(CKM_AES_GCM).
func agentUnwrap(name string, ct, iv []byte) ([]byte, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"value": base64.RawURLEncoding.EncodeToString(ct),
		"iv":    base64.RawURLEncoding.EncodeToString(iv),
	})
	u := agentBase() + "/keys/" + url.PathEscape(name) + "/unwrapKey"
	resp, err := httpClient.Post(u, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent unwrap: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Value == "" {
		return nil, fmt.Errorf("agent unwrap: bad response: %s", string(body))
	}
	return b64any(out.Value)
}

// agentDestroy deletes the named key in the vault. Backs C_DestroyObject (the
// operator app was granted DeleteKey in mgmt ba76b02).
func agentDestroy(name string) error {
	req, err := http.NewRequest(http.MethodDelete, agentBase()+"/keys/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("agent destroy: HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func b64any(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}
