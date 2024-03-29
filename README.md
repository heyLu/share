# share - share files

A tiny personal minimalistic file-sharing service.  Written in Go, minimal dependencies.

![A screenshort of the page](./screenshot.png)

## Try it out!

```
docker run -it --rm -p 9999:9999 ghcr.io/heylu/share:main
```

Alternatively, clone the repo and run it using `go run .`.

## Configuration

- command line:

	```
	-addr string
	      The address the server is listening on. (default "localhost:9999")
	-uploads-dir string
	      The directory to store the uploads in. (default "./uploads/")
	```
- `BASE_URL` (environment)
- `upload-secret.txt` (a secret string that needs to be specified to be able to upload)
	- empty by default, allowing uploads by everyone
- `admin-secret.txt` (optional, allows viewing usage stats at `/stats` with user `admin` + admin-secret)
- code-only:
	- max upload size (50mb)
	- rate limit (1 upload request per 10 seconds)
	- expiry (14 days)

## Features

(Unchecked items are not implemented yet.)

- [x] upload only with password
- [x] upload rate limiting
- [ ] set content type for downloads
- [x] delete files after N days
- [x] admin stats (rate limiting, uploads, num downloads)
- [ ] password encryption (optional, encrypted with password on disk, crypto/aes?)
	- seems extremely tricky, consider using WebCryptoAPI implementation from firefox send?
		- would like to keep it server-side though, to avoid JS as we did so far...
	- could do an "obfuscation" method for pseudo-security, i.e. security against novices, like me

### Encryption ideas

- encryption *at rest*, i.e. the server gets sent the plaintext
	- malicious code/servers could record the plaintext
- crypto/aes (with `sha256(password)` as key) + cipher.NewOTR
- password is also checked using bcrypt before attempting decryption
