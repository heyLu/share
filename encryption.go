package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
)

var HashCost = bcrypt.DefaultCost

func Encrypt(input io.Reader, output io.Writer, password string) (hashedPassword []byte, err error) {
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(password), HashCost)
	if err != nil {
		return nil, fmt.Errorf("could not hash password: %s", err)
	}
	if len(bcryptHash) != 60 {
		return nil, fmt.Errorf("bcrypt hash must be 60 bytes")
	}

	aesKey := sha256.Sum256([]byte(password))
	if len(aesKey) != 32 {
		return nil, fmt.Errorf("aes key must be 32 bytes")
	}

	aesCipher, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("could not create cipher: %s", err)
	}

	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(aesCipher, iv[:])
	writer := &cipher.StreamWriter{S: stream, W: output}

	_, err = io.Copy(writer, input)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt data: %s", err)
	}

	return bcryptHash, err
}

func Decrypt(input io.Reader, output io.Writer, hashedPassword []byte, password string) error {
	err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		return fmt.Errorf("hash does not match password: %s", err)
	}

	aesKey := sha256.Sum256([]byte(password))
	if len(aesKey) != 32 {
		return fmt.Errorf("aes key must be 32 bytes")
	}

	aesCipher, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return fmt.Errorf("could not create cipher: %s", err)
	}

	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(aesCipher, iv[:])
	reader := &cipher.StreamReader{S: stream, R: input}

	_, err = io.Copy(output, reader)
	if err != nil {
		return fmt.Errorf("could not decrypt data: %s", err)
	}

	return nil
}
