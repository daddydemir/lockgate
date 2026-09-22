// Package secure contains standard crypto primitives and strict path matching.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"
)

func Random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Token() string        { return "lg_app_" + Random(32) }
func Hash(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
func VerifyToken(token string, hash []byte) bool {
	return strings.HasPrefix(token, "lg_app_") && subtle.ConstantTimeCompare(Hash(token), hash) == 1
}
func Password(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return "$argon2id$v=19$m=65536,t=3,p=2$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
}
func VerifyPassword(password, encoded string) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 6 || p[1] != "argon2id" || p[2] != "v=19" || p[3] != "m=65536,t=3,p=2" {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(p[4])
	if e != nil || len(salt) != 16 {
		return false
	}
	expected, e := base64.RawStdEncoding.DecodeString(p[5])
	if e != nil || len(expected) != 32 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

var pathRE = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:[./][A-Za-z0-9_-]+)*$`)

func ValidPath(p string) bool {
	return len(p) > 0 && len(p) <= 512 && pathRE.MatchString(p) && !strings.Contains(p, "..")
}
func ValidPattern(p string) bool {
	return ValidPath(p) || strings.HasSuffix(p, "/*") && ValidPath(strings.TrimSuffix(p, "/*"))
}
func Allowed(patterns []string, p string) bool {
	if !ValidPath(p) {
		return false
	}
	for _, pattern := range patterns {
		if pattern == p || strings.HasSuffix(pattern, "/*") && strings.HasPrefix(p, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}

// KeyProvider can be implemented by a KMS later; the MVP uses one file key.
type KeyProvider interface {
	Current() (string, []byte, error)
	Key(version string) ([]byte, error)
}
type FileKey struct{ key []byte }

func LoadFile(path string) (*FileKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.New("cannot read master key file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("master key file must have mode 0600 or stricter")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read master key file")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("master key must be a base64 encoded 32-byte key")
	}
	return &FileKey{key: key}, nil
}
func (k *FileKey) Current() (string, []byte, error) { return "file-v1", k.key, nil }
func (k *FileKey) Key(v string) ([]byte, error) {
	if v != "file-v1" {
		return nil, errors.New("unknown master key version")
	}
	return k.key, nil
}

type Envelope struct {
	Ciphertext, Nonce, EncryptedDEK []byte
	Algorithm, KeyVersion           string
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid encryption key length")
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}
func Seal(k KeyProvider, plaintext []byte, path string, version int) (Envelope, error) {
	var e Envelope
	kv, key, err := k.Current()
	if err != nil {
		return e, err
	}
	wrap, err := gcm(key)
	if err != nil {
		return e, err
	}
	dek := make([]byte, 32)
	if _, err = rand.Read(dek); err != nil {
		return e, err
	}
	defer clear(dek)
	data, err := gcm(dek)
	if err != nil {
		return e, err
	}
	aad := []byte(fmt.Sprintf("lockgate:%s:%d:%s", path, version, kv))
	nonce := make([]byte, data.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return e, err
	}
	wn := make([]byte, wrap.NonceSize())
	if _, err = rand.Read(wn); err != nil {
		return e, err
	}
	return Envelope{data.Seal(nil, nonce, plaintext, aad), nonce, wrap.Seal(wn, wn, dek, aad), "AES-256-GCM", kv}, nil
}
func Open(k KeyProvider, e Envelope, path string, version int) ([]byte, error) {
	if e.Algorithm != "AES-256-GCM" {
		return nil, errors.New("unsupported encryption algorithm")
	}
	key, err := k.Key(e.KeyVersion)
	if err != nil {
		return nil, err
	}
	wrap, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(e.EncryptedDEK) < wrap.NonceSize()+wrap.Overhead() {
		return nil, errors.New("invalid wrapped key")
	}
	aad := []byte(fmt.Sprintf("lockgate:%s:%d:%s", path, version, e.KeyVersion))
	dek, err := wrap.Open(nil, e.EncryptedDEK[:wrap.NonceSize()], e.EncryptedDEK[wrap.NonceSize():], aad)
	if err != nil {
		return nil, errors.New("cannot unwrap secret key")
	}
	defer clear(dek)
	data, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	if len(e.Nonce) != data.NonceSize() {
		return nil, errors.New("invalid nonce")
	}
	plain, err := data.Open(nil, e.Nonce, e.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("cannot decrypt secret version")
	}
	return plain, nil
}
