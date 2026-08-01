package sshconfig

import (
	"bytes"
	"errors"

	"golang.org/x/crypto/ssh"
)

func ValidatePublicKey(data []byte, expectedFingerprint string) error {
	publicKey, _, options, rest, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(data))
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("invalid SSH public-key file")
	}
	if expectedFingerprint != "" && ssh.FingerprintSHA256(publicKey) != expectedFingerprint {
		return errors.New("SSH public-key fingerprint does not match configuration")
	}
	return nil
}
