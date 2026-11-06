<?php
/**
 * ZubQuant Interactive Cross-Language Test Lab (JS Browser <-> PHP Server + Pro Multi-Recipient)
 * URL: https://wp.zubaer.local/wp-content/plugins/zubquant/lab.php
 *
 * @package ZubQuantWP
 */

declare(strict_types=1);

require_once __DIR__ . '/includes/Crypto/Keccak.php';
require_once __DIR__ . '/includes/Crypto/MLKem768.php';
require_once __DIR__ . '/includes/Crypto/XWing.php';
require_once __DIR__ . '/includes/Crypto/MLDsa65.php';
require_once __DIR__ . '/includes/Crypto/ZubQuant.php';

use Zubaer\ZubQuant\ZubQuant;

// Handle AJAX cross-language verification requests from the Browser JS SDK
if ( 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
	header( 'Content-Type: application/json; charset=utf-8' );
	$raw  = (string) file_get_contents( 'php://input' );
	$body = json_decode( $raw, true );
	$mode = $body['mode'] ?? '';

	try {
		if ( 'php_open_js_envelope' === $mode ) {
			// Browser sealed with JS `ZubQuant.seal()` -> PHP opens with `ZubQuant::open()`
			$opened = ZubQuant::open( (string) $body['envelope'], (string) $body['privateKey'], array( 'parseJson' => true ) );
			// PHP also signs a receipt with ML-DSA-65 for Browser JS to verify!
			$sig_keys = ZubQuant::generateSigningKeyPair();
			$signed   = ZubQuant::sign(
				array(
					'status'         => 'Decrypted by PHP 8.4 Server',
					'original_data'  => $opened,
					'php_version'    => PHP_VERSION,
					'verified_at_utc'=> gmdate( 'c' ),
				),
				$sig_keys['signingKey']
			);
			echo json_encode(
				array(
					'ok'             => true,
					'decryptedByPhp' => $opened,
					'phpVerifyKey'   => $sig_keys['verifyKey'],
					'phpSignedToken' => $signed,
				)
			);
			exit;
		}

		if ( 'php_seal_for_js' === $mode ) {
			// Browser sends only its Public Key -> PHP seals a secret payload for Browser JS to decrypt!
			$envelope = ZubQuant::seal(
				array(
					'from'      => 'PHP Backend (Zubaer\\ZubQuant)',
					'algorithm' => 'X-Wing (ML-KEM-768 + X25519 + AES-256-GCM)',
					'secret'    => 'Quantum-Safe Payload #' . random_int( 1000, 9999 ),
					'timestamp' => gmdate( 'c' ),
				),
				(string) $body['publicKey']
			);
			echo json_encode(
				array(
					'ok'          => true,
					'phpEnvelope' => $envelope,
				)
			);
			exit;
		}

		echo json_encode( array( 'ok' => false, 'error' => 'Unknown mode' ) );
	} catch ( Throwable $e ) {
		echo json_encode( array( 'ok' => false, 'error' => $e->getMessage() ) );
	}
	exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>ZubQuant — Interactive Post-Quantum Test Lab (JS ⇄ PHP)</title>
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f0f2f5; color: #1d2327; margin: 0; padding: 32px; }
		.container { max-width: 960px; margin: 0 auto; }
		.card { background: #fff; border: 1px solid #dcdcde; border-radius: 10px; padding: 22px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
		h1 { margin-top: 0; font-size: 24px; }
		h2 { margin-top: 0; font-size: 18px; color: #135e96; }
		button { background: #2271b1; color: #fff; border: none; padding: 10px 16px; border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; margin-right: 8px; }
		button:hover { background: #135e96; }
		pre { background: #1e1e2e; color: #a6e3a1; padding: 14px; border-radius: 6px; overflow-x: auto; font-size: 12.5px; line-height: 1.5; }
		.badge { display: inline-block; background: #edfaef; color: #007017; border: 1px solid #00a32a; padding: 3px 10px; border-radius: 99px; font-size: 12px; font-weight: 600; }
	</style>
</head>
<body>
<div class="container">
	<div class="card">
		<span class="badge">NIST FIPS 203 (ML-KEM-768) + X25519 + FIPS 204 (ML-DSA-65)</span>
		<h1 style="margin-top:10px;">ZubQuant — Live Browser (NPM) ⇄ Server (PHP) Interoperability Lab</h1>
		<p>This page tests your <strong>NPM Browser Bundle (<code>zubquant.browser.js</code>)</strong> communicating with your <strong>PHP Backend (<code>Zubaer\ZubQuant\ZubQuant</code>)</strong> in real time.</p>
		<button id="run-all-btn">▶ Run Live Browser ⇄ PHP Post-Quantum Roundtrip Tests</button>
	</div>

	<div class="card">
		<h2>Test 1: Seal in Browser (JS) → Decrypt on Server (PHP) + Sign Receipt (ML-DSA-65) → Verify in Browser (JS)</h2>
		<pre id="out-test1">Click "Run Live Browser ⇄ PHP Post-Quantum Roundtrip Tests" above...</pre>
	</div>

	<div class="card">
		<h2>Test 2: Seal on Server (PHP) using Browser's Public Key → Decrypt Locally in Browser (JS)</h2>
		<pre id="out-test2">Waiting...</pre>
	</div>
</div>

<script src="assets/js/zubquant.browser.js"></script>
<script>
document.getElementById('run-all-btn').addEventListener('click', async function () {
	const out1 = document.getElementById('out-test1');
	const out2 = document.getElementById('out-test2');

	try {
		out1.textContent = 'Generating X-Wing (ML-KEM-768 + X25519) keypair in Browser...';
		const t0 = performance.now();
		const kp = window.ZubQuant.generateKeyPair();
		const payload = {
			test: 'Browser JS -> PHP Server',
			site: window.location.origin,
			secretNote: 'Harvest-Now-Decrypt-Later Immune!'
		};
		const envelope = await window.ZubQuant.seal(payload, kp.publicKey);
		const t1 = performance.now();

		const res1 = await fetch(window.location.href, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				mode: 'php_open_js_envelope',
				envelope,
				privateKey: kp.privateKey
			})
		}).then(r => r.json());

		// Verify PHP's ML-DSA-65 signature right in the browser!
		const sigCheck = window.ZubQuant.verify(res1.phpSignedToken, res1.phpVerifyKey, { parseJson: true });

		out1.textContent = JSON.stringify({
			browserKeygenAndSealTimeMs: Math.round(t1 - t0),
			publicKeyPrefix: kp.publicKey.slice(0, 44) + '...',
			zpq1EnvelopePrefix: envelope.slice(0, 64) + '...',
			phpServerDecrypted: res1.decryptedByPhp,
			browserVerifiedPhpMlDsa65Signature: sigCheck
		}, null, 2);

		// Test 2: PHP seals for Browser Public Key -> Browser opens with Private Key
		out2.textContent = 'Requesting PHP server to encapsulate payload for Browser Public Key...';
		const res2 = await fetch(window.location.href, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				mode: 'php_seal_for_js',
				publicKey: kp.publicKey
			})
		}).then(r => r.json());

		const browserDecrypted = await window.ZubQuant.open(res2.phpEnvelope, kp.privateKey, { parseJson: true });
		out2.textContent = JSON.stringify({
			phpGeneratedEnvelopePrefix: res2.phpEnvelope.slice(0, 64) + '...',
			browserDecryptedPayload: browserDecrypted
		}, null, 2);
	} catch (err) {
		out1.textContent = 'Error: ' + err.message;
	}
});
</script>
</body>
</html>

