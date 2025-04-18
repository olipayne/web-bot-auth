# web-bot-auth Caddy Plugin

![GitHub License](https://img.shields.io/github/license/cloudflareresearch/web-bot-auth)
![GitHub Release](https://img.shields.io/github/v/release/cloudflareresearch/web-bot-auth)

[Caddy plugin](https://caddyserver.com/docs/extending-caddy) extending Caddy configuration to allow for validation of web-bot-auth as defined in [draft-meunier-web-bot-auth-architecture](https://thibmeu.github.io/http-message-signatures-directory/draft-meunier-web-bot-auth-architecture.html).

## Tables of Content

- [Features](#features)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [License](#license)

## Features

This is an example plugin and only supports Ed25519. You can find a test key in [Appendix B.1.4 of RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421#name-example-ed25519-test-key).

* `httpsig` configuration hook
* Parse HTTP Message Signatures directory
* Block request without a valid signature

## Usage

First, you need to install [xcaddy](https://github.com/caddyserver/xcaddy)

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

Then you build caddy

```bash
xcaddy build latest --with github.com/cloudflareresearch/web-bot-auth/examples/caddy-plugin=./
```

And finally, you run caddy

```bash
./caddy run --config Caddyfile
```

To generate a signed request, you can use the sibling [browser extension](../browser-extension).

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the Apache 2.0 license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache 2.0 licensed as above, without any additional terms or conditions.
