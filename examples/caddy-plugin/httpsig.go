package httpsig

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("httpsig", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var m Middleware
		err := m.UnmarshalCaddyfile(h.Dispenser)
		return &m, err
	},
	)
}

type Directory struct {
	Keys    []json.RawMessage `json:"keys"`
	Purpose *string           `json:"purpose,omitempty"`
}

// Middleware struct to hold the configuration for the handler
type Middleware struct {
	DirectoryBase string `json:"directory_base"`
	validator     *SignatureValidator
}

// CaddyModule function to provide module information to Caddy
func (m Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.httpsig",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision method for setting up the validator with the public key
func (m *Middleware) Provision(ctx caddy.Context) error {
	// consider the case where the directory ios localhost
	resp, err := http.Get("https://" + m.DirectoryBase + "/.well-known/http-message-signatures-directory")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var dir Directory
	err = json.NewDecoder(resp.Body).Decode(&dir)
	if err != nil {
		return err
	}

	validator, err := NewValidator(dir.Keys[0])
	if err != nil {
		return err
	}
	m.validator = validator
	return nil
}

// ServeHTTP method to handle the request and validate the signature
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if err := m.validator.Validate(r); err != nil {
		fmt.Println(err)
		http.Error(w, "Invalid HTTP signature", http.StatusUnauthorized)
		return nil
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile method to allow configuration via the Caddyfile
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "directory_base":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.DirectoryBase = d.Val()
			default:
				return d.Errf("unknown option '%s'", d.Val())
			}
		}
	}
	return nil
}
