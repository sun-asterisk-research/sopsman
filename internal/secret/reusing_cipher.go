package secret

import (
	"fmt"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
)

// reusingCipher is a sops.Cipher that remembers every ciphertext it decrypts
// and hands each one back, at most once, when the same plaintext is encrypted
// at the same path. Everything else is encrypted with a fresh random IV.
//
// aes.Cipher has a similar built-in IV stash, but it is a plain map: list
// items share a path (sops paths omit list indexes), so duplicate values in a
// list would all get the same IV and identical ciphertext, revealing that they
// are equal. Consuming each recorded ciphertext once avoids that.
//
// Reusing a ciphertext is only valid with the data key it was created with.
type reusingCipher struct {
	decrypter aes.Cipher
	// encrypter never decrypts, so its own IV stash stays empty and every IV
	// it generates is random.
	encrypter aes.Cipher
	recorded  map[string][]string
}

func newReusingCipher() *reusingCipher {
	return &reusingCipher{
		decrypter: aes.NewCipher(),
		encrypter: aes.NewCipher(),
		recorded:  map[string][]string{},
	}
}

func reuseKey(plaintext interface{}, additionalData string) string {
	var v string
	switch p := plaintext.(type) {
	case sops.Comment:
		v = "comment\x00" + p.Value
	case []byte:
		v = "bytes\x00" + string(p)
	case time.Time:
		v = "time\x00" + p.Format(time.RFC3339Nano)
	default:
		v = fmt.Sprintf("%T\x00%v", p, p)
	}
	return additionalData + "\x00" + v
}

func (c *reusingCipher) Decrypt(ciphertext string, key []byte, additionalData string) (interface{}, error) {
	plaintext, err := c.decrypter.Decrypt(ciphertext, key, additionalData)
	if err == nil && ciphertext != "" {
		k := reuseKey(plaintext, additionalData)
		c.recorded[k] = append(c.recorded[k], ciphertext)
	}
	return plaintext, err
}

func (c *reusingCipher) Encrypt(plaintext interface{}, key []byte, additionalData string) (string, error) {
	k := reuseKey(plaintext, additionalData)
	if q := c.recorded[k]; len(q) > 0 {
		c.recorded[k] = q[1:]
		return q[0], nil
	}
	return c.encrypter.Encrypt(plaintext, key, additionalData)
}
