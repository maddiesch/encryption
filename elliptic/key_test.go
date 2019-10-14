package encryption

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEllipticKey(t *testing.T) {
	t.Run("ECurve256", func(t *testing.T) {
		t.Run("generating keys", func(t *testing.T) {
			_, err := GenerateKey(ECurve256)

			assert.NoError(t, err)
		})

		t.Run("encoding private key", func(t *testing.T) {
			out, err := GenerateKey(ECurve256)

			require.NoError(t, err)

			_, err = out.PrivatePEM()
			assert.NoError(t, err)
		})

		t.Run("encoding public key", func(t *testing.T) {
			out, err := GenerateKey(ECurve256)

			require.NoError(t, err)

			_, err = out.PublicPEM()
			assert.NoError(t, err)
		})

		publicPem := []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYSGizrLnFzflhpqyryv6MEwQW3Ar\n+uZ5q0AyU3WMDVyzvaw+9VJ1dlDSpbaTzIYEY3shQIhgXK6neERDlHWw6Q==\n-----END PUBLIC KEY-----")
		privatePem := []byte("-----BEGIN PRIVATE KEY-----\nMHcCAQEEIAmQK6NwQnHadbYIjb/UeIVFrZUcAtI85ITelsD9hDZCoAoGCCqGSM49\nAwEHoUQDQgAEYSGizrLnFzflhpqyryv6MEwQW3Ar+uZ5q0AyU3WMDVyzvaw+9VJ1\ndlDSpbaTzIYEY3shQIhgXK6neERDlHWw6Q==\n-----END PRIVATE KEY-----")

		t.Run("decoding private key", func(t *testing.T) {
			_, err := DecodePrivateKey(privatePem)

			assert.NoError(t, err)
		})

		t.Run("decoding public key", func(t *testing.T) {
			_, err := DecodePublicKey(publicPem)

			assert.NoError(t, err)
		})

		t.Run("signing a message", func(t *testing.T) {
			key, _ := DecodePrivateKey(privatePem)

			_, err := SignMessage(key, []byte("my super secret message"))

			assert.NoError(t, err)
		})

		t.Run("signing a message", func(t *testing.T) {
			sig, _ := base64.StdEncoding.DecodeString("cLNsoeDsdUkefZuC9PwoRINOnzHPR/W9xnvyFrOd72SnTSWVo5pBEO31vQaUjZbguU2BBAEtII23gGyjGenIog==")
			key, _ := DecodePublicKey(publicPem)

			err := VerifySignature(key, []byte("my super secret message"), sig)

			assert.NoError(t, err)
		})
	})
}
