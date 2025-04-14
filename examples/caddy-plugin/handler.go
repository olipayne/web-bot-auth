package httpsig

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/remitly-oss/httpsig-go"
	"github.com/remitly-oss/httpsig-go/keyman"
	"github.com/remitly-oss/httpsig-go/keyutil"
)

type SignatureValidator struct {
	Verifier *httpsig.Verifier
}

func NewValidator(keyData []byte) (*SignatureValidator, error) {
	pubKey, err := keyutil.ReadPublicKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	kf := keyman.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
		"test-key-ed25519": {
			KeyID:  "test-key-ed25519",
			Algo:   httpsig.Algo_ED25519,
			PubKey: pubKey,
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
