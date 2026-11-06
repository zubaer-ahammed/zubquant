=== ZubQuant — Post-Quantum Encryption & Zero-Knowledge Vault ===
Contributors: zubaerahammed
Tags: post-quantum, encryption, security, privacy, ml-kem
Requires at least: 6.2
Tested up to: 6.8
Requires PHP: 8.1
Stable tag: 1.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Zero-Knowledge Post-Quantum Form & Database Encryption (NIST FIPS 203 ML-KEM-768 + X25519 Hybrid X-Wing) and FIPS 204 ML-DSA-65 Signed Audit Logs.

== Description ==

**ZubQuant** brings NIST-standardized Post-Quantum Cryptography (PQC) and true Zero-Knowledge data sovereignty to WordPress.

Unlike conventional encryption plugins that store the symmetric AES decryption key in `wp-config.php` or the database (meaning any attacker who compromises the server can immediately decrypt every record), **ZubQuant** uses the **IETF X-Wing Hybrid Post-Quantum KEM (`ML-KEM-768` + `X25519` + `AES-256-GCM`)**:

* **Zero-Knowledge Architecture:** Only your **Public Encapsulation Key (`zpq1_pub_...`)** lives on the WordPress server.
* **Auto-Protection for Existing Forms:** Automatically seals submissions from **Contact Form 7**, **WPForms**, **Elementor Forms**, **Ninja Forms**, and **Fluent Forms**—plus includes the drop-in `[zubquant_secure_form]` shortcode.
* **Admin Secret & Credential Vault:** Lock confidential admin notes, API keys, and recovery codes directly inside your Quantum Safe, with 1-click JSON backup export.
* **Harvest-Now-Decrypt-Later Protection:** Even if an attacker steals your entire MySQL database and `wp-config.php` today and stores it for a future Quantum Computer, the data cannot be decrypted without your offline Private Key (`zpq1_sec_...`).
* **In-Browser Admin Decryption:** Decrypt vault entries directly inside your browser in `wp-admin`—your raw private key never touches the server.
* **Post-Quantum Intrusion & Audit Logs (`ML-DSA-65`):** Admin logins, failed login attempts, new user registrations, role escalations, and plugin changes are hash-chained (`SHA3-256`) and digitally signed with NIST FIPS 204 `ML-DSA-65`.

== Installation ==

1. Upload the `zubquant` folder to `/wp-content/plugins/`.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Visit **ZubQuant PQC** in `wp-admin` and click **Generate X-Wing Keypair in Browser**.
4. Place `[zubquant_secure_form]` on any page or post.

== Changelog ==

= 1.0.0 =
* Initial release with NIST FIPS 203 (ML-KEM-768), IETF X-Wing Hybrid KEM, AES-256-GCM, and NIST FIPS 204 (ML-DSA-65) support.

