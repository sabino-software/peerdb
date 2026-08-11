package pluginruntime

import (
	"encoding/hex"
	"testing"
)

func TestComputeNonceProofKnownVector(t *testing.T) {
	token := make([]byte, LaunchTokenSize)
	nonce := make([]byte, HandshakeNonceSize)
	for index := range token {
		token[index] = byte(index)
		nonce[index] = byte(index + 32)
	}

	proof, err := ComputeNonceProof(token, nonce)
	if err != nil {
		t.Fatalf("ComputeNonceProof returned an error: %v", err)
	}
	const expected = "62215de7bddcea7e2c4047ff6bb94f8d18262fc8b3f3648134bb7d44158ff84d"
	if hex.EncodeToString(proof) != expected {
		t.Fatalf("proof = %x, want %s", proof, expected)
	}
	if !VerifyNonceProof(token, nonce, proof) {
		t.Fatal("VerifyNonceProof rejected a valid proof")
	}
	proof[0] ^= 0xff
	if VerifyNonceProof(token, nonce, proof) {
		t.Fatal("VerifyNonceProof accepted a modified proof")
	}
}

func TestComputeNonceProofRequiresExactLengths(t *testing.T) {
	valid := make([]byte, LaunchTokenSize)
	if _, err := ComputeNonceProof(valid[:len(valid)-1], valid); err == nil {
		t.Fatal("short launch token was accepted")
	}
	if _, err := ComputeNonceProof(valid, valid[:len(valid)-1]); err == nil {
		t.Fatal("short nonce was accepted")
	}
}

func TestParseIdentityAcceptsCanonicalManifestDigest(t *testing.T) {
	const digestHex = "af94ac57a9abce57bc1204f4b01eee6135d23e54e3bfcb4736007b6ec45175f0"
	identity, err := ParseIdentity("io.peerdb.example", "1.2.3", "sha256:"+digestHex)
	if err != nil {
		t.Fatalf("ParseIdentity: %v", err)
	}
	if got, want := identity.Digest(), "sha256:"+digestHex; got != want {
		t.Fatalf("Digest() = %q, want %q", got, want)
	}
	if got := identity.DigestHex(); got != digestHex {
		t.Fatalf("DigestHex() = %q, want %q", got, digestHex)
	}
}
