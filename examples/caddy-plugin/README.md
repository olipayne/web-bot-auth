Test

Install xcaddy
```
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

Build caddy
```
xcaddy build latest --with github.com/thibmeu/http-message-signatures-examples/caddy=./
```

Run caddy
```
./caddy run --config Caddyfile
```

Use the extension to send an HTTP Message signature