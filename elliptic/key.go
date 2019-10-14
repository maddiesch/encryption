package encryption

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// ECurve is the type of elliptic curve to use for creating key pairs
type ECurve int

const (
	_ ECurve = iota

	// ECurveInvalid is the ECurve for an unsupported elliptic curve size
	ECurveInvalid

	// ECurve256 a 256-bit elliptic curve
	ECurve256
)

func (e ECurve) curve() elliptic.Curve {
	switch e {
	case ECurve256:
		return elliptic.P256()
	default:
		panic(fmt.Errorf("the elliptic curve is not supported %d", e))
	}
}

// ECurveForSize returns the elliptic curve's type for a given size
func ECurveForSize(size int) ECurve {
	switch size {
	case 256:
		return ECurve256
	default:
		return ECurveInvalid
	}
}

var (
	// ErrInvalidKeySize is returned when the key size is not supported by the function
	ErrInvalidKeySize = errors.New("the key is not a supported size")

	// ErrInvalidSignature is returned when the signature does not match the the expected signature for the public key
	ErrInvalidSignature = errors.New("the signature is not valid for the message")
)

// GenerateKeyOutput contains the keys returned by a GenerateKey call
type GenerateKeyOutput struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// PrivatePEM marshales the private key into x509 pem format
func (g *GenerateKeyOutput) PrivatePEM() ([]byte, error) {
	x509Private, err := x509.MarshalECPrivateKey(g.PrivateKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Private}), nil
}

// PublicPEM marshales the public key into x509 pem format
func (g *GenerateKeyOutput) PublicPEM() ([]byte, error) {
	x509Public, err := x509.MarshalPKIXPublicKey(g.PublicKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509Public}), nil
}

// GenerateKey creates a new key pair with the passed type
func GenerateKey(ec ECurve) (*GenerateKeyOutput, error) {
	pubCurve := ec.curve()

	privKey := new(ecdsa.PrivateKey)
	privKey, err := ecdsa.GenerateKey(pubCurve, rand.Reader)

	if err != nil {
		return nil, err
	}

	pubKey := privKey.PublicKey

	return &GenerateKeyOutput{
		PrivateKey: privKey,
		PublicKey:  &(pubKey),
	}, nil
}

// DecodePrivateKey performs the steps required to decode a private key from
// a x509 PEM file
func DecodePrivateKey(input []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(input)
	if block == nil {
		return nil, errors.New("failed to find a PEM file in input")
	}

	pKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pKey, nil
}

// DecodePublicKey performs the steps required to decode a public key from
// a x509 PEM file
func DecodePublicKey(input []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(input)
	if block == nil {
		return nil, errors.New("failed to find a PEM file in input")
	}

	pKeyMaybe, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pKey, ok := pKeyMaybe.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("the encoded public key is not an ECDSA key")
	}

	return pKey, nil
}

// HashMessage performs hasing on the message to get it the correct size for the
// signature.
func HashMessage(ec ECurve, message []byte) ([]byte, error) {
	switch ec {
	case ECurve256:
		hash := sha256.Sum256(message)
		return hash[:], nil
	default:
		return nil, ErrInvalidKeySize
	}
}

// SignMessage performs the signature for the message
func SignMessage(key *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash, err := HashMessage(ECurveForSize(key.Params().BitSize), message)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, key, hash)
	if err != nil {
		return nil, err
	}

	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)

	return signature, nil
}

// VerifySignature performs the verification of a signature
func VerifySignature(key *ecdsa.PublicKey, message, signature []byte) error {
	hash, err := HashMessage(ECurveForSize(key.Params().BitSize), message)
	if err != nil {
		return err
	}

	r := big.NewInt(0).SetBytes(signature[:len(signature)/2])
	s := big.NewInt(0).SetBytes(signature[len(signature)/2:])

	if ecdsa.Verify(key, hash, r, s) {
		return nil
	}

	return ErrInvalidSignature
}
