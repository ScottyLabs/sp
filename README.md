# Service Provider

## Setup

```bash
openssl req -x509 -newkey rsa:2048 -keyout privatekey.pem -out publickey.cer -days 7300
```

Then, use these commands to generate the values for the `PRIVATE_KEY_BASE64` and `PUBLIC_KEY_BASE64` environment variables:

```bash
base64 -i privatekey.pem
base64 -i publickey.cer
```

If you are running this project on Mac, you may need to install `xmlsec`:

```bash
brew install libxmlsec1
```
