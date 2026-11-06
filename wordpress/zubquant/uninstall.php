<?php
/**
 * Uninstall handler for ZubQuant.
 *
 * @package ZubQuantWP
 */

declare(strict_types=1);

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'zubquant_version' );
delete_option( 'zubquant_public_key' );
delete_option( 'zubquant_locked_private_key' );
delete_option( 'zubquant_audit_verify_key' );
delete_option( 'zubquant_audit_signing_key' );

