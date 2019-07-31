package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestEncryptAndDecrypt(t *testing.T) {
	HashCost = bcrypt.MinCost

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

func BenchmarkEncryptAndDecrypt(b *testing.B) {
	HashCost = bcrypt.MinCost

	inputFileName := os.Getenv("TEST_INPUT_FILE")
	if inputFileName == "" {
		b.Fatal("set TEST_INPUT_FILE to a big file to benchmark encryption")
	}

	// write a big file to disk for comparison
	b.Run("write big file", func(b *testing.B) {
		f, err := os.Open(inputFileName)
		if err != nil {
			b.Fatalf("could not open %q: %s", inputFileName, err)
		}

		out, err := os.OpenFile("bench-write", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
		if err != nil {
			b.Fatalf("could not create %q: %s", "bench-write", err)
		}

		_, err = io.Copy(out, f)
		if err != nil {
			b.Fatalf("could not write: %s", err)
		}

		err = out.Sync()
		if err != nil {
			b.Fatalf("could not sync: %s", err)
		}

		reportBytes(b, f)
	})

	password := "password"
	var hashedPassword []byte

	b.Run("encrypt", func(b *testing.B) {
		f, err := os.Open(inputFileName)
		if err != nil {
			b.Fatalf("could not open %q: %s", inputFileName, err)
		}

		out, err := os.OpenFile("bench-encrypted", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
		if err != nil {
			b.Fatalf("could not create %q: %s", "bench-write", err)
		}

		hashedPassword, err = Encrypt(f, out, password)
		if err != nil {
			b.Fatalf("could not encrypt: %s", err)
		}

		err = out.Sync()
		if err != nil {
			b.Fatalf("could not sync: %s", err)
		}

		reportBytes(b, f)
	})

	b.Run("decrypt", func(b *testing.B) {
		f, err := os.Open("bench-encrypted")
		if err != nil {
			b.Fatalf("could not open %q: %s", inputFileName, err)
		}

		out, err := os.OpenFile("bench-decrypted", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
		if err != nil {
			b.Fatalf("could not create %q: %s", "bench-write", err)
		}

		err = Decrypt(f, out, hashedPassword, password)
		if err != nil {
			b.Fatalf("could not decrypt: %s", err)
		}

		err = out.Sync()
		if err != nil {
			b.Fatalf("could not sync: %s", err)
		}

		reportBytes(b, f)
	})

	removeFile(b, "bench-write")
	removeFile(b, "bench-encrypted")
	removeFile(b, "bench-decrypted")
}

func reportBytes(b *testing.B, f *os.File) {
	b.StopTimer()
	defer b.StartTimer()
	stat, err := f.Stat()
	if err != nil {
		b.Fatalf("could not stat: %s", err)
	}
	b.SetBytes(stat.Size())
}

func removeFile(b *testing.B, name string) {
	b.StopTimer()
	defer b.StartTimer()
	err := os.Remove(name)
	if err != nil {
		b.Fatalf("could not remove %q: %s", name, err)
	}
}
