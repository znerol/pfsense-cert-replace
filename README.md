# pfsense-cert-replace

Replace existing pfSense TLS certificate with new one read from stdin

## Installation

1. Copy `cert-replace.php` to `/usr/local/bin/cert-replace.php`.
2. `chmod +x /usr/local/bin/cert-replace.php

## Usage

Local:

```
/usr/local/bin/cert-replace.php certificate-name < /path-to-cert.
```

Remote:

```
cat /path-to-cert.pem | ssh root@pfsense /usr/local/bin/cert-replace.php certificate-name
```
