# share - share files

## Configuration

- `BASE_URL` (environment)
- `upload-secret.txt` (a secret string that needs to be specified to be able to upload)
	- empty by default
- code-only:
	- max upload size (50mb)
	- uploads directory (`./uploads`)
	- rate limit (1 upload request per 10 seconds)
	- expiry (14 days)

## Features

(Unchecked items are not implemented yet.

- [x] upload only with password
- [x] upload rate limiting
- [ ] set content type for downloads
- [ ] delete files after N days
- [ ] admin stats (rate limiting, uploads, num downloads)
