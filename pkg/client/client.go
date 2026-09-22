// Package client provides the same token-based integration for local, container,
// and remote applications. Get waits for human approval and respects its context.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrDenied = errors.New("lockgate: access denied by administrator")

type Config struct {
	URL, Token   string
	HTTPClient   *http.Client
	PollInterval time.Duration
}
type Client struct{ config Config }
type Secrets map[string]map[string]string
type response struct {
	Status     string  `json:"status"`
	RequestID  string  `json:"request_id"`
	RetryAfter int     `json:"retry_after"`
	Secrets    Secrets `json:"secrets"`
}

// GetConfigured asks LockGate for every current secret assigned to the
// application token. Application identity and environment are resolved by the
// server; callers do not send either value.
func (c *Client) GetConfigured(ctx context.Context) (Secrets, error) {
	return c.waitForSecrets(ctx, nil, true)
}

// GetConfig returns the application's single configured secret bundle. It is
// the simplest startup API. Use GetConfigured when an application is assigned
// more than one bundle.
func (c *Client) GetConfig(ctx context.Context) (map[string]string, error) {
	secrets, err := c.GetConfigured(ctx)
	if err != nil {
		return nil, err
	}
	if len(secrets) != 1 {
		return nil, errors.New("lockgate: GetConfig requires exactly one configured secret bundle")
	}
	for _, values := range secrets {
		return values, nil
	}
	return nil, errors.New("lockgate: approved response contains no configured secrets")
}

func New(c Config) *Client {
	if c.PollInterval < time.Second {
		c.PollInterval = 3 * time.Second
	}
	c.URL = strings.TrimRight(c.URL, "/")
	return &Client{config: c}
}
func (c *Client) Get(ctx context.Context, paths ...string) (Secrets, error) {
	return c.WaitForSecrets(ctx, paths)
}

// GetSecret requests one named secret bundle and returns its key/value pairs.
// It is a convenience wrapper around WaitForSecrets for applications that use
// one bundle at startup.
func (c *Client) GetSecret(ctx context.Context, path string) (map[string]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("lockgate: secret path is required")
	}
	secrets, err := c.WaitForSecrets(ctx, []string{path})
	if err != nil {
		return nil, err
	}
	return secrets[path], nil
}
func (c *Client) request(ctx context.Context, method, path, key string, body []byte) (response, error) {
	var out response
	base, e := url.Parse(c.config.URL)
	if e != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Path != "" {
		return out, errors.New("lockgate: URL must be an http(s) origin")
	}
	if c.config.Token == "" {
		return out, errors.New("lockgate: application token is required")
	}
	req, e := http.NewRequestWithContext(ctx, method, c.config.URL+path, bytes.NewReader(body))
	if e != nil {
		return out, errors.New("lockgate: invalid request")
	}
	req.Header.Set("Authorization", "Bearer "+c.config.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	// Copy the client's configuration and forbid redirects so tokens cannot leak
	// to another origin. Each request is bounded even if ctx has no deadline.
	hc := http.Client{Timeout: 15 * time.Second}
	if c.config.HTTPClient != nil {
		hc = *c.config.HTTPClient
		if hc.Timeout == 0 {
			hc.Timeout = 15 * time.Second
		}
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, e := hc.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		return out, errors.New("lockgate: server unreachable or request timed out")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 && res.StatusCode != 202 {
		return out, fmt.Errorf("lockgate: request rejected (HTTP %d)", res.StatusCode)
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(&out); e != nil {
		return out, errors.New("lockgate: invalid server response")
	}
	return out, nil
}
func (c *Client) WaitForSecrets(ctx context.Context, paths []string) (Secrets, error) {
	return c.waitForSecrets(ctx, paths, false)
}

func (c *Client) waitForSecrets(ctx context.Context, paths []string, configured bool) (Secrets, error) {
	if len(paths) == 0 {
		if !configured {
			return nil, errors.New("lockgate: at least one secret path is required")
		}
	}
	body, e := json.Marshal(struct {
		Secrets []string `json:"secrets,omitempty"`
	}{paths})
	if e != nil {
		return nil, e
	}
	b := make([]byte, 24)
	if _, e = rand.Read(b); e != nil {
		return nil, errors.New("lockgate: cannot generate request identity")
	}
	key := hex.EncodeToString(b)
	out, e := c.request(ctx, http.MethodPost, "/api/v1/access", key, body)
	for e == nil {
		switch out.Status {
		case "approved":
			if configured && len(out.Secrets) == 0 {
				return nil, errors.New("lockgate: approved response contains no configured secrets")
			}
			for _, p := range paths {
				if _, ok := out.Secrets[p]; !ok {
					return nil, errors.New("lockgate: approved response is missing required secrets")
				}
			}
			return out.Secrets, nil
		case "denied":
			return nil, ErrDenied
		case "waiting_approval":
			if out.RequestID == "" || strings.ContainsAny(out.RequestID, "/?#") {
				return nil, errors.New("lockgate: missing or invalid request ID")
			}
			delay := c.config.PollInterval
			if out.RetryAfter > 0 && out.RetryAfter <= 60 && time.Duration(out.RetryAfter)*time.Second > delay {
				delay = time.Duration(out.RetryAfter) * time.Second
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
			out, e = c.request(ctx, http.MethodGet, "/api/v1/access/"+url.PathEscape(out.RequestID), "", nil)
		case "revoked":
			out, e = c.request(ctx, http.MethodPost, "/api/v1/access", key, body)
		default:
			return nil, errors.New("lockgate: unexpected access status")
		}
	}
	return nil, e
}
