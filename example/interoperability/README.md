# interoperability example

## Appendix: Generate self-signed certificate by OpenSSL

```shell
$ openssl genpkey -algorithm RSA -out key.pem
$ openssl req -new -x509 -days 365 -key key.pem -out localhost-unasuke-dev.crt -subj "/C=JP/L=Tokyo/O=unasuke/CN=localhost.unasuke.dev"
$ openssl x509 -text -in localhost-unasuke-dev.crt -noout # for verify
```
