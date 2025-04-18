# web-bot-auth Browser extension

![GitHub License](https://img.shields.io/github/license/cloudflareresearch/web-bot-auth)
![GitHub Release](https://img.shields.io/github/v/release/cloudflareresearch/web-bot-auth)

Chrome browser extension adding HTTP Message Signature on all outgoing requests as defined by [RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421). Specification is in [draft-meunier-web-bot-auth-architecture](https://thibmeu.github.io/http-message-signatures-directory/draft-meunier-web-bot-auth-architecture.html).

## Tables of Content

- [Features](#features)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [License](#license)

## Features

- Chrome Manifest v3 extension
- RFC 9421 compatible `Signature` header
- CRX extension server

## Usage

If you don't have one, generate a signing key for your extension

```shell
npm run generate-signing-key
```

Then build, bundle, and sign the Chrome extension

```shell
npm run bundle:chrome
```

This extension requires an [entreprise policy](https://support.google.com/chrome/a/answer/187202?hl=en) to be configured on your Chrome. It requires that you configure your Chrome instance with a policy to force install the extension.

In a distinct terminal, run `npm run start:config`. This ensures Chrome can install your extension.

On Linux

```shell
mkdir -p /etc/opt/chrome/policies/managed
cp config/chromium/policy.json /etc/opt/chrome/policies/managed/policy.json
```

On macOS

```shell
mkdir -p /Library/Managed\ Preferences/
cp config/chromium/com.google.Chrome.managed.plist /Library/Managed\ Preferences/
```

You can confirm the policy is installed by navigating to `chrome://policy/`.

> You might have to change the forced_install ID. To find the ID of your extension, drag and drop it in Chrome, look at the ID, then replace instances of `fkgomfknhcfpepcgkimebggnfgkbghii`

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the Apache 2.0 license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache 2.0 licensed as above, without any additional terms or conditions.
