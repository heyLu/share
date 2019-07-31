package main

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestEncryptAndDecrypt(t *testing.T) {
	testCases := []struct {
		name            string
		plaintext       string
		passwordEncrypt string
		passwordDecrypt string
		errEncrypt      string
		errDecrypt      string
	}{
		{"encrypt and decrypt works", "this is my secret!", "password", "password", "", ""},
		{"decrypt with wrong password", "this is my secret!", "password", "wrong", "", "hash does not match password"},
	}

	HashCost = bcrypt.MinCost

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			in := bytes.NewBufferString(tc.plaintext)
			encryptedBuf := new(bytes.Buffer)

			hashedPassword, err := Encrypt(in, encryptedBuf, tc.passwordEncrypt)
			expectErrorMatch(t, tc.errEncrypt, err)

			if bytes.Contains(encryptedBuf.Bytes(), []byte(tc.plaintext)) {
				t.Fatalf("ciphertext contains plaintext!\nplaintext: %q\nciphertext:\n%s", tc.plaintext, encryptedBuf.String())
			}

			decryptedBuf := new(bytes.Buffer)
			err = Decrypt(encryptedBuf, decryptedBuf, hashedPassword, tc.passwordDecrypt)
			expectErrorMatch(t, tc.errDecrypt, err)

			if tc.errDecrypt == "" && tc.plaintext != decryptedBuf.String() {
				t.Fatalf("decrypted text does not match plaintext:\nplaintext: %q\ndecrypted: %q", tc.plaintext, decryptedBuf.String())
			}
		})
	}
}

func expectErrorMatch(t *testing.T, errorMatch string, err error) {
	if errorMatch == "" && err != nil {
		t.Fatalf("unexpected error: encrypt: %s", err)
	}
	if errorMatch != "" {
		if err == nil {
			t.Fatalf("expected error but got none")
		}
		if !strings.Contains(err.Error(), errorMatch) {
			t.Fatalf("expected error to match %q, but was: %s", errorMatch, err)
		}
	}

}
