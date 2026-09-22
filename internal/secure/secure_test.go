package secure

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestEnvelope(t *testing.T) {
	k := &FileKey{key: bytes.Repeat([]byte{1}, 32)}
	plain := []byte(`{"PASSWORD":"never-plaintext-in-db"}`)
	e, err := Seal(k, plain, "projects/a/db", 1)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Open(k, e, "projects/a/db", 1)
	if err != nil || !bytes.Equal(out, plain) {
		t.Fatal("roundtrip failed", err)
	}
	other, err := Seal(k, plain, "projects/a/db", 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(e.Ciphertext, other.Ciphertext) || bytes.Equal(e.EncryptedDEK, other.EncryptedDEK) {
		t.Fatal("encryption must use fresh DEK and nonces")
	}
	for _, tt := range []struct {
		name, path string
		v          int
		k          *FileKey
	}{{"wrong path", "projects/b/db", 1, k}, {"wrong version", "projects/a/db", 2, k}, {"wrong key", "projects/a/db", 1, &FileKey{key: bytes.Repeat([]byte{2}, 32)}}} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Open(tt.k, e, tt.path, tt.v); err == nil {
				t.Fatal("accepted invalid context")
			}
		})
	}
	for _, field := range []string{"ciphertext", "nonce", "dek", "algorithm", "key_version"} {
		t.Run(field, func(t *testing.T) {
			v := e
			switch field {
			case "ciphertext":
				v.Ciphertext = append([]byte(nil), e.Ciphertext...)
				v.Ciphertext[0] ^= 1
			case "nonce":
				v.Nonce = []byte{1}
			case "dek":
				v.EncryptedDEK = []byte{1}
			case "algorithm":
				v.Algorithm = "unknown"
			case "key_version":
				v.KeyVersion = "unknown"
			}
			if _, err := Open(k, v, "projects/a/db", 1); err == nil {
				t.Fatal("accepted tampered envelope")
			}
		})
	}
}
func TestTokens(t *testing.T) {
	a, b := Token(), Token()
	if a == b {
		t.Fatal("tokens repeated")
	}
	if !VerifyToken(a, Hash(a)) || VerifyToken(b, Hash(a)) || VerifyToken("", Hash("")) {
		t.Fatal("token verification incorrect")
	}
	if bytes.Contains(Hash(a), []byte(a)) {
		t.Fatal("raw token stored")
	}
}
func TestPassword(t *testing.T) {
	h := Password("correct horse battery staple")
	if !VerifyPassword("correct horse battery staple", h) || VerifyPassword("wrong", h) || VerifyPassword("x", "malformed") {
		t.Fatal("password verification incorrect")
	}
}
func TestPaths(t *testing.T) {
	for _, tt := range []struct {
		path  string
		allow bool
	}{{"projects/a/db", true}, {"projects/a/prod/db", true}, {"projects/ab/db", false}, {"projects/b/db", false}, {"projects/a", false}, {"projects/a/../b", false}, {"/projects/a/db", false}, {"projects/a//db", false}, {"projects/a/db/", false}, {"projects/a/%2e", false}} {
		if got := Allowed([]string{"projects/a/*"}, tt.path); got != tt.allow {
			t.Errorf("%q: got %v", tt.path, got)
		}
	}
	if !Allowed([]string{"single/path"}, "single/path") || Allowed([]string{"single/path"}, "single/path/child") {
		t.Fatal("exact matching broken")
	}
	if ValidPattern("*") || ValidPattern("projects/*/db") {
		t.Fatal("unsupported pattern accepted")
	}
}
func TestFileKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(make([]byte, 32))), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(p); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, 0644)
	if _, err := LoadFile(p); err == nil {
		t.Fatal("readable key accepted")
	}
}
