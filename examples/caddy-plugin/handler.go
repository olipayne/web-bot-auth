package httpsig

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/remitly-oss/httpsig-go"
	"github.com/remitly-oss/httpsig-go/keyman"
)

type SignatureValidator struct {
	Verifier *httpsig.Verifier
}

func NewValidator(keyData []byte) (*SignatureValidator, error) {
	pubKey, err := jwk.ParseKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	thumbprint, err := pubKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key id from key: %w", err)
	}
	keyid := base64.RawURLEncoding.EncodeToString(thumbprint)
	pk, _ := jwk.PublicRawKeyOf(pubKey)

	kf := keyman.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
		keyid: {
			KeyID:  keyid,
			Algo:   httpsig.Algo_ED25519,
			PubKey: pk,
		},
	})

	verifier, err := httpsig.NewVerifier(kf, httpsig.VerifyProfile{
		AllowedAlgorithms:         []httpsig.Algorithm{httpsig.Algo_ED25519},
		RequiredFields:            httpsig.Fields("@authority"),
		RequiredMetadata:          httpsig.DefaultVerifyProfile.RequiredMetadata,
		DisallowedMetadata:        []httpsig.Metadata{},
		DisableMultipleSignatures: httpsig.DefaultVerifyProfile.DisableMultipleSignatures,
		CreatedValidDuration:      time.Hour * 5, // Signatures must have been created within within the last 5 minutes
		DateFieldSkew:             time.Minute,   // If the created parameter is present, the Date header cannot be more than a minute off.
	})
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	return &SignatureValidator{Verifier: verifier}, nil
}

func (v *SignatureValidator) Validate(r *http.Request) error {
	result, err := v.Verifier.Verify(r)
	if err != nil {
		return err
	}

	if len(result.InvalidSignatures) > 0 {
		return errors.New("invalid signatures")
	}

	return nil
}
