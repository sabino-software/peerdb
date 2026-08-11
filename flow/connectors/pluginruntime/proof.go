package pluginruntime

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

var defaultRandomReader = rand.Reader

// ComputeNonceProof is the normative launch proof algorithm:
//
//	HMAC-SHA256(key=launch_token,
//	            message=nonce)
//
// Both token and nonce must be exactly 32 bytes. This intentionally matches the
// language-neutral protocol contract; changing the message bytes would make
// independently implemented plugin SDKs fail authentication.
func ComputeNonceProof(launchToken, nonce []byte) ([]byte, error) {
	if len(launchToken) != LaunchTokenSize {
		return nil, errors.New("launch token must be exactly 32 bytes")
	}
	if len(nonce) != HandshakeNonceSize {
		return nil, errors.New("handshake nonce must be exactly 32 bytes")
	}
	mac := hmac.New(sha256.New, launchToken)
	_, _ = mac.Write(nonce)
	return mac.Sum(nil), nil
}

func VerifyNonceProof(launchToken, nonce, proof []byte) bool {
	expected, err := ComputeNonceProof(launchToken, nonce)
	return err == nil && hmac.Equal(expected, proof)
}
