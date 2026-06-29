// Package pwd generates random passwords/tokens with crypto/rand.
package pwd

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

const (
	lower = "abcdefghijkmnpqrstuvwxyz"
	upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	digit = "23456789"
	sym   = "!@#$%^&*-_=+"
)

// Strong returns a random password of length n (min 16) containing at least one
// lower, upper, digit and symbol — satisfies typical ppolicy quality checks.
func Strong(n int) (string, error) {
	if n < 16 {
		n = 16
	}
	classes := []string{lower, upper, digit, sym}
	all := lower + upper + digit + sym

	b := make([]byte, n)
	for i, cls := range classes {
		idx, err := index(len(cls))
		if err != nil {
			return "", err
		}
		b[i] = cls[idx]
	}
	for i := len(classes); i < n; i++ {
		idx, err := index(len(all))
		if err != nil {
			return "", err
		}
		b[i] = all[idx]
	}
	for i := n - 1; i > 0; i-- { // Fisher-Yates shuffle
		j, err := index(i + 1)
		if err != nil {
			return "", err
		}
		b[i], b[j] = b[j], b[i]
	}
	return string(b), nil
}

// Hex returns a random lowercase-hex token of nBytes*2 characters.
func Hex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func index(limit int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}
