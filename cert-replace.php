#!/usr/local/bin/php -f
<?php
/**
 * cert-replace.php
 *
 * Replace existing pfSense TLS certificate with new one read from stdin.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once("certs.inc");
require_once("config.inc");
require_once("util.inc");

// Usage.
if ($argc !== 2) {
    echo "Usage: php " . $argv[0] . " certificate-name\n";
    exit(1);
}

// Lookup existing TLS certificate or csr and key.
$cert = lookup_cert_by_name($argv[1]);
if (empty($cert['item']['prv'])) {
    echo "No such certificate configured: " . $argv[1] . "\n";
    exit(1);
}

// Verify TLS certificate.
$pemcert = stream_get_contents(STDIN);
if (strpos($pemcert, "-----BEGIN CERTIFICATE-----") === FALSE || strrpos($pemcert, "-----END CERTIFICATE-----") === FALSE) {
    echo "This certificate does not appear to be valid.\n";
    exit(1);
}

// Verify TLS key.
$pemkey = base64_decode($cert['item']['prv']);
if (strpos($pemkey, "-----BEGIN PRIVATE KEY-----") === FALSE || strrpos($pemkey, "-----END PRIVATE KEY-----") === FALSE) {
    echo "The private key does not appear to be valid.\n";
    exit(1);
}

// Verify that TLS certificate and key match.
if (!openssl_x509_check_private_key($pemcert, $pemkey)) {
    echo "The private key does not match the certificate.\n";
    exit(1);
}

// Ensure that the new certificate is actually fresh.
if (!empty($cert['item']['crt'])) {
    $pemlast = base64_decode($cert['item']['crt']);

    if (strpos($pemlast, "-----BEGIN CERTIFICATE-----") === FALSE || strrpos($pemlast, "-----END CERTIFICATE-----") === FALSE) {
        echo "The existing certificate does not appear to be valid.\n";
        exit(1);
    }

    if (openssl_x509_fingerprint($pemlast) === openssl_x509_fingerprint($pemcert)) {
        echo "The certificate is already imported.\n";
        exit();
    }
}

// Install new certificate and write config.
csr_complete($cert['item'], $pemcert);
config_set_path("cert/{$cert['idx']}", $cert['item']);
write_config(sprintf(gettext("Replaced HTTPS certificate (%s)"), $cert['item']['refid']));

// Reload webui if appropriate.
if (is_webgui_cert($cert['item']['refid'])) {
    log_error(gettext("webConfigurator configuration has changed. Restarting webConfigurator."));
    send_event("service restart webgui");
}

echo "Completed! New certificate installed.\n";
