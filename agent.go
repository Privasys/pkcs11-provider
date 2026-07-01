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

// agentKey is one key as the agent's GET /keys lists it.
type agentKey struct {
	Name string `json:"name"`
	Kty  string `json:"kty"` // "EC" (P-256 signing) | "oct" (AES) | ...
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

// agentSign asks the agent to sign msg with the named key. alg is a JOSE alg
// (ES256). The returned signature is raw r||s (64 bytes for P-256), which is
// exactly what PKCS#11 CKM_ECDSA* expects — no DER re-encoding.
func agentSign(name, alg string, msg []byte) ([]byte, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"alg":   alg,
		"value": base64.RawURLEncoding.EncodeToString(msg),
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
	sig, err := base64.RawURLEncoding.DecodeString(out.Value)
	if err != nil {
		// tolerate std base64 too
		if sig, err = base64.StdEncoding.DecodeString(out.Value); err != nil {
			return nil, fmt.Errorf("agent sign: decode signature: %w", err)
		}
	}
	return sig, nil
}
