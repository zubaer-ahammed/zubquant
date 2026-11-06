<?php
/**
 * Plugin Name:       ZubQuant — Post-Quantum Encryption & Zero-Knowledge Vault
 * Plugin URI:        https://wp.zubaer.com/zubquant/
 * Description:       NIST FIPS 203 (ML-KEM-768 + X25519 Hybrid X-Wing) Zero-Knowledge Form & Database Vault and FIPS 204 (ML-DSA-65) Quantum-Signed Security Audit Logs.
 * Version:           1.0.0
 * Requires at least: 6.2
 * Requires PHP:      8.1
 * Author:            Md. Zubaer Ahammed
 * Author URI:        https://zubaer.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       zubquant
 * Domain Path:       /languages
 *
 * @package ZubQuantWP
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'ZUBQUANT_VERSION', '1.0.0' );
define( 'ZUBQUANT_FILE', __FILE__ );
define( 'ZUBQUANT_PATH', plugin_dir_path( __FILE__ ) );
define( 'ZUBQUANT_URL', plugin_dir_url( __FILE__ ) );
define( 'ZUBQUANT_BASENAME', plugin_basename( __FILE__ ) );

// Load Core Post-Quantum Cryptography Engine (Zubaer\ZubQuant)
require_once ZUBQUANT_PATH . 'includes/Crypto/Keccak.php';
require_once ZUBQUANT_PATH . 'includes/Crypto/MLKem768.php';
require_once ZUBQUANT_PATH . 'includes/Crypto/XWing.php';
require_once ZUBQUANT_PATH . 'includes/Crypto/MLDsa65.php';
require_once ZUBQUANT_PATH . 'includes/Crypto/ZubQuant.php';
require_once ZUBQUANT_PATH . 'includes/Plugin.php';

/**
 * Return the singleton plugin instance.
 */
function zubquant(): \ZubQuantWP\Plugin {
	return \ZubQuantWP\Plugin::instance();
}

zubquant()->boot();

register_activation_hook(
	__FILE__,
	static function (): void {
		\ZubQuantWP\Plugin::activate();
	}
);

