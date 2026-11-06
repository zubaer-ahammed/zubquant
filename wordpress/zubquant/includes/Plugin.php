<?php
/**
 * Main ZubQuant WordPress Plugin Controller.
 *
 * Features a beginner-friendly 1-Click Guided Onboarding Wizard ("Simple Mode")
 * alongside an expandable "Advanced & Auditor Mode" for technical users.
 *
 * @package ZubQuantWP
 */

declare(strict_types=1);

namespace ZubQuantWP;

use Zubaer\ZubQuant\ZubQuant;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin {

	private static ?self $instance = null;

	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public static function activate(): void {
		self::ensure_tables();

		// Auto-generate ML-DSA-65 Audit Signing Keypair if not set yet.
		if ( false === get_option( 'zubquant_audit_verify_key', false ) ) {
			$sig_keys = ZubQuant::generateSigningKeyPair();
			update_option( 'zubquant_audit_verify_key', $sig_keys['verifyKey'], false );
			update_option( 'zubquant_audit_signing_key', $sig_keys['signingKey'], false );
		}

		update_option( 'zubquant_version', ZUBQUANT_VERSION, false );
	}

	public static function ensure_tables(): void {
		global $wpdb;
		$charset_collate = $wpdb->get_charset_collate();
		$vault_table     = $wpdb->prefix . 'zubquant_vault';
		$audit_table     = $wpdb->prefix . 'zubquant_audit_log';

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$sql_vault = "CREATE TABLE {$vault_table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			source varchar(100) NOT NULL DEFAULT 'secure_form',
			subject varchar(255) NOT NULL DEFAULT '',
			sealed_envelope longtext NOT NULL,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY source (source)
		) {$charset_collate};";

		$sql_audit = "CREATE TABLE {$audit_table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			event_type varchar(100) NOT NULL,
			actor_id bigint(20) unsigned NOT NULL DEFAULT 0,
			prev_hash varchar(128) NOT NULL DEFAULT '',
			signed_token longtext NOT NULL,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY event_type (event_type)
		) {$charset_collate};";

		dbDelta( $sql_vault );
		dbDelta( $sql_audit );
	}

	public function boot(): void {
		add_action( 'admin_menu', array( $this, 'register_admin_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		add_action( 'admin_post_zubquant_save_keys', array( $this, 'handle_save_keys' ) );
		add_action( 'admin_post_zubquant_seed_demo', array( $this, 'handle_seed_demo' ) );
		add_action( 'admin_post_zubquant_add_secret', array( $this, 'handle_add_secret' ) );
		add_action( 'admin_post_zubquant_export_vault', array( $this, 'handle_export_vault' ) );
		add_action( 'admin_post_zubquant_upgrade_my_password', array( $this, 'handle_upgrade_my_password' ) );
		add_action( 'admin_post_zubquant_delete_entry', array( $this, 'handle_delete_entry' ) );
		add_action( 'admin_post_zubquant_bulk_delete_entries', array( $this, 'handle_bulk_delete_entries' ) );
		add_action( 'admin_post_zubquant_clear_demos', array( $this, 'handle_clear_demos' ) );
		add_shortcode( 'zubquant_secure_form', array( $this, 'render_secure_form_shortcode' ) );
		add_action( 'init', array( $this, 'handle_frontend_form_submission' ) );

		// 1. Automatic Zero-Knowledge Form Protection Hooks (CF7, WPForms, Elementor, Ninja Forms, Fluent Forms)
		add_action( 'wpcf7_before_send_mail', array( $this, 'capture_cf7_submission' ), 10, 1 );
		add_action( 'wpforms_process_complete', array( $this, 'capture_wpforms_submission' ), 10, 4 );
		add_action( 'elementor_pro/forms/new_record', array( $this, 'capture_elementor_submission' ), 10, 2 );
		add_action( 'ninja_forms_after_submission', array( $this, 'capture_ninja_forms_submission' ), 10, 1 );
		add_action( 'fluentform/submission_inserted', array( $this, 'capture_fluent_forms_submission' ), 10, 3 );

		// 2. Quantum-Hardened Password & Session Shield (NIST FIPS 202 SHA3-512 + Argon2id + FIPS 204 ML-DSA-65)
		add_filter( 'wp_authenticate_user', array( $this, 'verify_quantum_password_shield' ), 20, 2 );
		add_action( 'wp_login', array( $this, 'auto_upgrade_password_on_login' ), 5, 2 );
		add_action( 'after_password_reset', array( $this, 'upgrade_password_after_reset' ), 10, 2 );

		// 3. Quantum-Signed Security & Intrusion Audit Hooks (NIST FIPS 204 ML-DSA-65 + SHA3-256 Chain)
		add_action( 'wp_login', array( $this, 'log_user_login' ), 10, 2 );
		add_action( 'wp_login_failed', array( $this, 'log_login_failed' ), 10, 1 );
		add_action( 'user_register', array( $this, 'log_user_registered' ), 10, 1 );
		add_action( 'set_user_role', array( $this, 'log_user_role_changed' ), 10, 3 );
		add_action( 'activated_plugin', array( $this, 'log_plugin_activated' ), 10, 1 );
		add_action( 'deactivated_plugin', array( $this, 'log_plugin_deactivated' ), 10, 1 );

		/**
		 * Fires once ZubQuant Free has booted so ZubQuant Pro can attach integrations.
		 *
		 * @param Plugin $this Plugin instance.
		 */
		do_action( 'zubquant_booted', $this );
	}

	public function is_pro_licensed(): bool {
		return (bool) apply_filters( 'zubquant_pro_is_licensed', false );
	}

	/**
	 * Store a Zero-Knowledge Quantum-Sealed payload in wp_zubquant_vault using only the site's Public Key.
	 *
	 * @param string               $source  Integration source (e.g. 'secure_form', 'ninja_forms', 'elementor', 'woocommerce').
	 * @param string               $subject Human-readable label/title.
	 * @param array<string, mixed> $payload Sensitive fields to seal with X-Wing (ML-KEM-768 + X25519 + AES-256-GCM).
	 */
	public function store_vault_entry( string $source, string $subject, array $payload ): int {
		global $wpdb;
		$public_key = (string) get_option( 'zubquant_public_key', '' );
		if ( '' === $public_key ) {
			return 0;
		}

		$envelope = ZubQuant::seal( $payload, $public_key );
		$table    = $wpdb->prefix . 'zubquant_vault';

		$wpdb->insert(
			$table,
			array(
				'source'          => sanitize_key( $source ),
				'subject'         => sanitize_text_field( $subject ),
				'sealed_envelope' => $envelope,
				'created_at'      => current_time( 'mysql', true ),
			),
			array( '%s', '%s', '%s', '%s' )
		);

		return (int) $wpdb->insert_id;
	}

	/**
	 * Append a hash-chained, ML-DSA-65 post-quantum signed security event to wp_zubquant_audit_log.
	 *
	 * @param string               $event_type Event identifier.
	 * @param array<string, mixed> $details    Event metadata.
	 */
	public function record_quantum_audit_event( string $event_type, array $details ): void {
		global $wpdb;
		$signing_key = (string) get_option( 'zubquant_audit_signing_key', '' );
		if ( '' === $signing_key ) {
			return;
		}

		$table      = $wpdb->prefix . 'zubquant_audit_log';
		$last_token = (string) $wpdb->get_var( "SELECT signed_token FROM {$table} ORDER BY id DESC LIMIT 1" );
		$prev_hash  = '' !== $last_token ? hash( 'sha3-256', $last_token ) : str_repeat( '0', 64 );

		$actor_id = get_current_user_id();
		$record   = array(
			'event'     => $event_type,
			'actor_id'  => $actor_id,
			'prev_hash' => $prev_hash,
			'timestamp' => gmdate( 'c' ),
			'details'   => $details,
		);

		$signed_token = ZubQuant::sign( $record, $signing_key );

		$wpdb->insert(
			$table,
			array(
				'event_type'   => sanitize_key( $event_type ),
				'actor_id'     => $actor_id,
				'prev_hash'    => $prev_hash,
				'signed_token' => $signed_token,
				'created_at'   => current_time( 'mysql', true ),
			),
			array( '%s', '%d', '%s', '%s', '%s' )
		);
	}

	public function log_user_login( string $user_login, \WP_User $user ): void {
		if ( user_can( $user, 'manage_options' ) ) {
			$this->record_quantum_audit_event(
				'admin_login',
				array( 'user_login' => $user_login, 'user_id' => $user->ID )
			);
		}
	}

	public function log_login_failed( string $username ): void {
		$ip_raw  = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$ip_hash = '' !== $ip_raw ? substr( hash( 'sha3-256', $ip_raw . wp_salt() ), 0, 16 ) : 'unknown';
		$this->record_quantum_audit_event(
			'login_failed',
			array(
				'attempted_user' => sanitize_user( $username ),
				'ip_fingerprint' => $ip_hash,
			)
		);
	}

	public function log_user_registered( int $user_id ): void {
		$user = get_userdata( $user_id );
		$this->record_quantum_audit_event(
			'user_registered',
			array(
				'user_id'    => $user_id,
				'user_login' => $user ? $user->user_login : '',
				'roles'      => $user ? implode( ',', (array) $user->roles ) : '',
			)
		);
	}

	/**
	 * Log user role changes.
	 *
	 * @param int      $user_id   User ID.
	 * @param string   $role      New role.
	 * @param string[] $old_roles Previous roles.
	 */
	public function log_user_role_changed( int $user_id, string $role, array $old_roles ): void {
		$this->record_quantum_audit_event(
			'user_role_changed',
			array(
				'user_id'   => $user_id,
				'new_role'  => $role,
				'old_roles' => implode( ',', $old_roles ),
			)
		);
	}

	public function log_plugin_activated( string $plugin ): void {
		$this->record_quantum_audit_event(
			'plugin_activated',
			array( 'plugin' => $plugin )
		);
	}

	public function log_plugin_deactivated( string $plugin ): void {
		$this->record_quantum_audit_event(
			'plugin_deactivated',
			array( 'plugin' => $plugin )
		);
	}

	/**
	 * Auto-capture Contact Form 7 submissions into the Quantum Vault.
	 *
	 * @param object $contact_form WPCF7_ContactForm instance.
	 */
	public function capture_cf7_submission( $contact_form ): void {
		if ( ! class_exists( '\WPCF7_Submission' ) ) {
			return;
		}
		$submission = \WPCF7_Submission::get_instance();
		if ( ! $submission ) {
			return;
		}
		$posted_data = (array) $submission->get_posted_data();
		$cleaned     = array();
		foreach ( $posted_data as $key => $val ) {
			if ( str_starts_with( (string) $key, '_wpcf7' ) ) {
				continue;
			}
			$cleaned[ (string) $key ] = is_array( $val ) ? implode( ', ', $val ) : (string) $val;
		}
		$title = is_object( $contact_form ) && method_exists( $contact_form, 'title' )
			? (string) $contact_form->title()
			: 'Contact Form 7 Submission';
		$this->store_vault_entry( 'contact_form_7', $title, $cleaned );
	}

	/**
	 * Auto-capture WPForms submissions into the Quantum Vault.
	 *
	 * @param array<int|string, mixed> $fields    Sanitized entry field values.
	 * @param array<string, mixed>     $entry     Original $_POST global.
	 * @param array<string, mixed>     $form_data Form settings/data.
	 * @param int                      $entry_id  Entry ID.
	 */
	public function capture_wpforms_submission( array $fields, array $entry, array $form_data, int $entry_id ): void {
		unset( $entry, $entry_id );
		$cleaned = array();
		foreach ( $fields as $field ) {
			if ( is_array( $field ) && isset( $field['name'], $field['value'] ) ) {
				$cleaned[ (string) $field['name'] ] = (string) $field['value'];
			}
		}
		$title = isset( $form_data['settings']['form_title'] ) ? (string) $form_data['settings']['form_title'] : 'WPForms Submission';
		$this->store_vault_entry( 'wpforms', $title, $cleaned );
	}

	/**
	 * Auto-capture Elementor Forms submissions into the Quantum Vault.
	 *
	 * @param object $record  Elementor form record.
	 * @param object $handler Elementor form handler.
	 */
	public function capture_elementor_submission( $record, $handler ): void {
		unset( $handler );
		if ( ! is_object( $record ) || ! method_exists( $record, 'get' ) ) {
			return;
		}
		$raw_fields = $record->get( 'fields' );
		$cleaned    = array();
		if ( is_array( $raw_fields ) ) {
			foreach ( $raw_fields as $id => $field ) {
				$label               = is_array( $field ) && ! empty( $field['title'] ) ? (string) $field['title'] : (string) $id;
				$cleaned[ $label ] = is_array( $field ) && isset( $field['value'] ) ? $field['value'] : $field;
			}
		}
		$form_name = method_exists( $record, 'get_form_settings' ) ? (string) $record->get_form_settings( 'form_name' ) : '';
		$this->store_vault_entry( 'elementor_forms', $form_name ?: 'Elementor Form Submission', $cleaned );
	}

	/**
	 * Auto-capture Ninja Forms submissions into the Quantum Vault.
	 *
	 * @param array<string, mixed> $form_data Ninja Forms submission payload.
	 */
	public function capture_ninja_forms_submission( array $form_data ): void {
		$fields  = isset( $form_data['fields'] ) && is_array( $form_data['fields'] ) ? $form_data['fields'] : array();
		$cleaned = array();
		foreach ( $fields as $field ) {
			if ( is_array( $field ) && isset( $field['key'], $field['value'] ) ) {
				$cleaned[ (string) $field['key'] ] = $field['value'];
			}
		}
		$title = isset( $form_data['settings']['title'] ) ? (string) $form_data['settings']['title'] : 'Ninja Form Submission';
		$this->store_vault_entry( 'ninja_forms', $title, $cleaned );
	}

	/**
	 * Auto-capture Fluent Forms submissions into the Quantum Vault.
	 *
	 * @param int                  $entry_id  Entry ID.
	 * @param array<string, mixed> $form_data Submitted form data.
	 * @param object               $form      Fluent Form object.
	 */
	public function capture_fluent_forms_submission( int $entry_id, array $form_data, $form ): void {
		unset( $entry_id );
		$cleaned = array();
		foreach ( $form_data as $key => $val ) {
			if ( str_starts_with( (string) $key, '_' ) || 'fluentform' === substr( (string) $key, 0, 10 ) ) {
				continue;
			}
			$cleaned[ (string) $key ] = is_array( $val ) ? wp_json_encode( $val ) : (string) $val;
		}
		$title = is_object( $form ) && isset( $form->title ) ? (string) $form->title : 'Fluent Form Submission';
		$this->store_vault_entry( 'fluent_forms', $title, $cleaned );
	}

	/**
	 * Handle locking an Admin Secret Note / API Key / Credential into the Quantum Vault.
	 */
	public function handle_add_secret(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'zubquant' ) );
		}
		check_admin_referer( 'zubquant_add_secret_nonce' );

		$title    = isset( $_POST['zubquant_secret_title'] ) ? sanitize_text_field( wp_unslash( $_POST['zubquant_secret_title'] ) ) : '';
		$category = isset( $_POST['zubquant_secret_category'] ) ? sanitize_key( wp_unslash( $_POST['zubquant_secret_category'] ) ) : 'admin_secret';
		$secret   = isset( $_POST['zubquant_secret_body'] ) ? sanitize_textarea_field( wp_unslash( $_POST['zubquant_secret_body'] ) ) : '';

		if ( '' !== $title && '' !== $secret ) {
			$user = wp_get_current_user();
			$this->store_vault_entry(
				$category ?: 'admin_secret',
				$title,
				array(
					'Category' => strtoupper( str_replace( '_', ' ', $category ) ),
					'Title'    => $title,
					'Secret'   => $secret,
					'SavedBy'  => $user ? $user->user_login : 'admin',
					'Created'  => gmdate( 'Y-m-d H:i:s \U\T\C' ),
				)
			);
			$this->record_quantum_audit_event(
				'admin_secret_sealed',
				array( 'title' => $title, 'category' => $category )
			);
		}

		wp_safe_redirect( admin_url( 'admin.php?page=zubquant-vault&secret_saved=1' ) );
		exit;
	}

	/**
	 * Handle exporting the Quantum-Sealed Vault & Audit Log as an offline JSON backup.
	 */
	public function handle_export_vault(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'zubquant' ) );
		}
		check_admin_referer( 'zubquant_export_vault_nonce' );

		global $wpdb;
		$vault_table = $wpdb->prefix . 'zubquant_vault';
		$audit_table = $wpdb->prefix . 'zubquant_audit_log';

		$vault_rows = $wpdb->get_results( "SELECT * FROM {$vault_table} ORDER BY id DESC", ARRAY_A );
		$audit_rows = $wpdb->get_results( "SELECT * FROM {$audit_table} ORDER BY id DESC", ARRAY_A );

		$this->record_quantum_audit_event(
			'vault_backup_exported',
			array( 'vault_count' => is_array( $vault_rows ) ? count( $vault_rows ) : 0 )
		);

		$export = array(
			'format'              => 'zubquant-quantum-vault-backup-v1',
			'exported_at'         => gmdate( 'c' ),
			'site_url'            => home_url(),
			'public_key'          => (string) get_option( 'zubquant_public_key', '' ),
			'audit_verify_key'    => (string) get_option( 'zubquant_audit_verify_key', '' ),
			'quantum_vault_items' => $vault_rows ?: array(),
			'signed_audit_log'    => $audit_rows ?: array(),
		);

		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="zubquant-vault-backup-' . gmdate( 'Y-m-d' ) . '.json"' );
		echo wp_json_encode( $export, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		exit;
	}

	/**
	 * Compute the NIST FIPS 202 SHA3-512 pre-hash for a user password.
	 */
	private function compute_sha3_512_prehash( int $user_id, string $plain_password ): string {
		return hash_hmac( 'sha3-512', $plain_password, wp_salt( 'auth' ) . '|zubquant-pqc-pass|' . $user_id );
	}

	/**
	 * Upgrade a WordPress user account to the Quantum-Hardened Password & Session Shield
	 * (NIST FIPS 202 SHA3-512 + Memory-Hard Argon2id + NIST FIPS 204 ML-DSA-65 Signed Hash).
	 * Keeps wp_users.user_pass compatible with WordPress core so deactivating the plugin never locks out users.
	 */
	public function upgrade_user_password_to_quantum_shield( \WP_User $user, string $plain_password ): void {
		if ( '' === $plain_password ) {
			return;
		}

		// 1. If wp_users.user_pass is still a legacy MD5 ($P$ or $H$) hash, upgrade it to modern WP hash immediately.
		$current_hash = (string) $user->user_pass;
		if ( str_starts_with( $current_hash, '$P$' ) || str_starts_with( $current_hash, '$H$' ) || str_starts_with( $current_hash, '$1$' ) ) {
			global $wpdb;
			$new_wp_hash = wp_hash_password( $plain_password );
			$wpdb->update(
				$wpdb->users,
				array( 'user_pass' => $new_wp_hash ),
				array( 'ID' => $user->ID ),
				array( '%s' ),
				array( '%d' )
			);
			clean_user_cache( $user->ID );
		}

		// 2. Compute NIST FIPS 202 SHA3-512 pre-hash + Memory-Hard Argon2id hash.
		$prehash = $this->compute_sha3_512_prehash( (int) $user->ID, $plain_password );
		if ( defined( 'PASSWORD_ARGON2ID' ) ) {
			$pqc_hash = password_hash(
				$prehash,
				PASSWORD_ARGON2ID,
				array(
					'memory_cost' => 65536,
					'time_cost'   => 3,
					'threads'     => 1,
				)
			);
			$algo_label = 'SHA3-512 + Argon2id (64MB)';
		} else {
			$pqc_hash   = password_hash( $prehash, PASSWORD_BCRYPT, array( 'cost' => 12 ) );
			$algo_label = 'SHA3-512 + Bcrypt-12';
		}

		update_user_meta( $user->ID, '_zubquant_pqc_pass_hash', $pqc_hash );
		update_user_meta( $user->ID, '_zubquant_pqc_pass_algo', $algo_label );
		update_user_meta( $user->ID, '_zubquant_pqc_pass_updated', gmdate( 'c' ) );

		// 3. Sign the password hash & user binding with NIST FIPS 204 ML-DSA-65 so DB hash injection is detected.
		$signing_key = (string) get_option( 'zubquant_audit_signing_key', '' );
		if ( '' !== $signing_key ) {
			$sig_token = ZubQuant::sign(
				array(
					'uid'      => (int) $user->ID,
					'login'    => (string) $user->user_login,
					'pqc_hash' => $pqc_hash,
				),
				$signing_key
			);
			update_user_meta( $user->ID, '_zubquant_pqc_pass_sig', $sig_token );
		}
	}

	/**
	 * Verify Quantum-Hardened Password Shield (SHA3-512 + Argon2id + ML-DSA-65 signature) during authentication.
	 *
	 * @param \WP_User|\WP_Error $user     Authenticated user or error.
	 * @param string             $password Plaintext password submitted.
	 * @return \WP_User|\WP_Error
	 */
	public function verify_quantum_password_shield( $user, string $password ) {
		if ( is_wp_error( $user ) || ! ( $user instanceof \WP_User ) ) {
			return $user;
		}

		$pqc_hash = (string) get_user_meta( $user->ID, '_zubquant_pqc_pass_hash', true );
		if ( '' === $pqc_hash ) {
			// User hasn't been upgraded yet; auto_upgrade_password_on_login will upgrade them right after this hook!
			return $user;
		}

		// 1. Verify NIST FIPS 204 ML-DSA-65 signature over the stored password hash to prevent SQLi hash replacement.
		$sig_token  = (string) get_user_meta( $user->ID, '_zubquant_pqc_pass_sig', true );
		$verify_key = (string) get_option( 'zubquant_audit_verify_key', '' );
		if ( '' !== $sig_token && '' !== $verify_key ) {
			$verified = ZubQuant::verify( $sig_token, $verify_key );
			if ( empty( $verified['valid'] ) ) {
				$this->record_quantum_audit_event(
					'password_hash_tamper_blocked',
					array( 'user_id' => $user->ID, 'user_login' => $user->user_login )
				);
				return new \WP_Error(
					'zubquant_tampered_hash',
					__( 'Security Alert: ZubQuant detected an invalid ML-DSA-65 post-quantum signature on this account password hash.', 'zubquant' )
				);
			}
		}

		// 2. Verify password against NIST FIPS 202 SHA3-512 + Argon2id hash.
		$prehash = $this->compute_sha3_512_prehash( (int) $user->ID, $password );
		if ( ! password_verify( $prehash, $pqc_hash ) ) {
			$this->record_quantum_audit_event(
				'pqc_password_mismatch',
				array( 'user_id' => $user->ID, 'user_login' => $user->user_login )
			);
			return new \WP_Error(
				'zubquant_invalid_password',
				__( 'Invalid password (verified by ZubQuant SHA3-512 + Argon2id Quantum Shield).', 'zubquant' )
			);
		}

		return $user;
	}

	/**
	 * Automatically upgrade any user's password to SHA3-512 + Argon2id + ML-DSA-65 when they log in.
	 */
	public function auto_upgrade_password_on_login( string $user_login, \WP_User $user ): void {
		unset( $user_login );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$plain_password = isset( $_POST['pwd'] ) ? (string) wp_unslash( $_POST['pwd'] ) : '';
		if ( '' === $plain_password ) {
			return;
		}
		$existing_pqc = (string) get_user_meta( $user->ID, '_zubquant_pqc_pass_hash', true );
		$is_legacy    = str_starts_with( (string) $user->user_pass, '$P$' ) || str_starts_with( (string) $user->user_pass, '$H$' );
		if ( '' === $existing_pqc || $is_legacy ) {
			$this->upgrade_user_password_to_quantum_shield( $user, $plain_password );
			$this->record_quantum_audit_event(
				'password_quantum_upgraded',
				array( 'user_id' => $user->ID, 'trigger' => 'login_auto_upgrade' )
			);
		}
	}

	/**
	 * Automatically upgrade password when a user resets their password.
	 */
	public function upgrade_password_after_reset( \WP_User $user, string $new_pass ): void {
		$this->upgrade_user_password_to_quantum_shield( $user, $new_pass );
		$this->record_quantum_audit_event(
			'password_quantum_upgraded',
			array( 'user_id' => $user->ID, 'trigger' => 'password_reset' )
		);
	}

	/**
	 * Handle 1-click admin self-upgrade to SHA3-512 + Argon2id + ML-DSA-65 from the ZubQuant dashboard.
	 */
	public function handle_upgrade_my_password(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'zubquant' ) );
		}
		check_admin_referer( 'zubquant_upgrade_my_password_nonce' );

		$user         = wp_get_current_user();
		$current_pass = isset( $_POST['zubquant_current_wp_pass'] ) ? (string) wp_unslash( $_POST['zubquant_current_wp_pass'] ) : '';

		if ( ! $user || ! $user->exists() || '' === $current_pass || ! wp_check_password( $current_pass, $user->user_pass, $user->ID ) ) {
			wp_safe_redirect( admin_url( 'admin.php?page=zubquant&pass_upgrade_error=1' ) );
			exit;
		}

		$this->upgrade_user_password_to_quantum_shield( $user, $current_pass );
		$this->record_quantum_audit_event(
			'password_quantum_upgraded',
			array(
				'user_id'    => $user->ID,
				'user_login' => $user->user_login,
				'trigger'    => 'admin_dashboard_1click',
			)
		);

		wp_safe_redirect( admin_url( 'admin.php?page=zubquant&pass_upgraded=1' ) );
		exit;
	}

	/**
	 * Scan wp_users to report Quantum-Hardened (SHA3-512 + Argon2id) vs. Standard Bcrypt vs. Vulnerable Legacy MD5 ($P$) accounts.
	 *
	 * @return array<string, mixed>
	 */
	private function get_password_quantum_stats(): array {
		global $wpdb;
		$users = $wpdb->get_results( "SELECT ID, user_pass FROM {$wpdb->users}" );

		$total            = 0;
		$quantum_hardened = 0;
		$modern_bcrypt    = 0;
		$legacy_md5       = 0;

		if ( is_array( $users ) ) {
			foreach ( $users as $u ) {
				++$total;
				$uid      = (int) $u->ID;
				$pass     = (string) $u->user_pass;
				$pqc_hash = (string) get_user_meta( $uid, '_zubquant_pqc_pass_hash', true );

				if ( '' !== $pqc_hash ) {
					++$quantum_hardened;
				} elseif ( str_starts_with( $pass, '$P$' ) || str_starts_with( $pass, '$H$' ) || str_starts_with( $pass, '$1$' ) || 32 === strlen( $pass ) ) {
					++$legacy_md5;
				} else {
					++$modern_bcrypt;
				}
			}
		}

		$current_uid  = get_current_user_id();
		$current_algo = $current_uid > 0 ? (string) get_user_meta( $current_uid, '_zubquant_pqc_pass_algo', true ) : '';

		return array(
			'total'                 => $total,
			'quantum_hardened'      => $quantum_hardened,
			'modern_bcrypt'         => $modern_bcrypt,
			'legacy_md5'            => $legacy_md5,
			'current_user_hardened' => '' !== $current_algo,
			'current_user_algo'     => $current_algo ?: ( defined( 'PASSWORD_ARGON2ID' ) ? 'SHA3-512 + Argon2id (64MB)' : 'SHA3-512 + Bcrypt-12' ),
		);
	}

	public function register_admin_menu(): void {
		add_menu_page(
			__( 'ZubQuant Safe', 'zubquant' ),
			__( 'ZubQuant Safe', 'zubquant' ),
			'manage_options',
			'zubquant',
			array( $this, 'render_admin_page' ),
			'dashicons-shield-alt',
			65
		);

		add_submenu_page(
			'zubquant',
			__( 'Password & Login Shield — ZubQuant Safe', 'zubquant' ),
			__( '🔑 Password Shield', 'zubquant' ),
			'manage_options',
			'zubquant',
			array( $this, 'render_admin_page' )
		);

		add_submenu_page(
			'zubquant',
			__( 'Vault & Messages — ZubQuant Safe', 'zubquant' ),
			__( '📬 Vault & Messages', 'zubquant' ),
			'manage_options',
			'zubquant-vault',
			array( $this, 'render_vault_page' )
		);

		// Hidden alias so any existing links/bookmarks to page=zubquant-passwords continue to work seamlessly.
		add_submenu_page(
			null,
			__( 'Password & Login Shield — ZubQuant Safe', 'zubquant' ),
			__( '🔑 Password Shield', 'zubquant' ),
			'manage_options',
			'zubquant-passwords',
			array( $this, 'render_passwords_page' )
		);

		add_submenu_page(
			'zubquant',
			__( 'Security Audit Log — ZubQuant Safe', 'zubquant' ),
			__( '🛡️ Security Audit Log', 'zubquant' ),
			'manage_options',
			'zubquant-audit',
			array( $this, 'render_audit_page' )
		);

		add_submenu_page(
			'zubquant',
			__( 'Guide & Key Settings — ZubQuant Safe', 'zubquant' ),
			__( '⚙️ Guide & Settings', 'zubquant' ),
			'manage_options',
			'zubquant-settings',
			array( $this, 'render_settings_page' )
		);
	}

	public function render_vault_page(): void {
		$_GET['tab'] = 'vault';
		$this->render_admin_page();
	}

	public function render_passwords_page(): void {
		$_GET['tab'] = 'passwords';
		$this->render_admin_page();
	}

	public function render_audit_page(): void {
		$_GET['tab'] = 'audit';
		$this->render_admin_page();
	}

	public function render_settings_page(): void {
		$_GET['tab'] = 'settings';
		$this->render_admin_page();
	}

	public function enqueue_admin_assets( string $hook_suffix ): void {
		if ( ! str_contains( $hook_suffix, 'zubquant' ) ) {
			return;
		}
		$js_file = ZUBQUANT_PATH . 'assets/js/zubquant.browser.js';
		$ver     = file_exists( $js_file ) ? ZUBQUANT_VERSION . '.' . (string) filemtime( $js_file ) : ZUBQUANT_VERSION;
		wp_enqueue_script(
			'zubquant-browser-sdk',
			ZUBQUANT_URL . 'assets/js/zubquant.browser.js',
			array(),
			$ver,
			true
		);
	}

	public function handle_save_keys(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'zubquant' ) );
		}
		check_admin_referer( 'zubquant_save_keys_nonce' );

		self::ensure_tables();

		$public_key = isset( $_POST['zubquant_public_key'] )
			? sanitize_text_field( wp_unslash( $_POST['zubquant_public_key'] ) )
			: '';
		$locked_private_key = isset( $_POST['zubquant_locked_private_key'] )
			? sanitize_text_field( wp_unslash( $_POST['zubquant_locked_private_key'] ) )
			: '';

		if ( str_starts_with( $public_key, 'zpq1_pub_' ) ) {
			update_option( 'zubquant_public_key', $public_key, false );
		}
		if ( '' === $locked_private_key || str_starts_with( $locked_private_key, 'zpq1.locked-key.' ) ) {
			update_option( 'zubquant_locked_private_key', $locked_private_key, false );
		}

		$this->record_quantum_audit_event(
			'vault_activated',
			array( 'public_key_prefix' => substr( $public_key, 0, 24 ) )
		);

		// If onboarding requested automatic demo page & sample test message creation:
		if ( ! empty( $_POST['zubquant_onboarding_seed'] ) && str_starts_with( $public_key, 'zpq1_pub_' ) ) {
			$this->seed_demo_data();
			wp_safe_redirect( admin_url( 'admin.php?page=zubquant&onboarded=1' ) );
			exit;
		}

		wp_safe_redirect( admin_url( 'admin.php?page=zubquant&updated=1' ) );
		exit;
	}

	private function seed_demo_data(): void {
		$this->store_vault_entry(
			'welcome_demo',
			'Welcome to Your Quantum-Safe Vault!',
			array(
				'Sender'  => 'ZubQuant Security Assistant',
				'Status'  => 'Protected with Hybrid Post-Quantum Encryption',
				'Message' => 'Congratulations! Only your Master Password can unlock and read this message. Even if someone downloads your WordPress database, this message remains unreadable.',
				'Created' => gmdate( 'Y-m-d H:i:s \U\T\C' ),
			)
		);

		$existing_page_id = (int) get_option( 'zubquant_demo_page_id', 0 );
		if ( 0 === $existing_page_id || ! get_post( $existing_page_id ) ) {
			$existing_page_id = (int) wp_insert_post(
				array(
					'post_title'   => 'Send a Confidential Message',
					'post_content' => '[zubquant_secure_form]',
					'post_status'  => 'publish',
					'post_type'    => 'page',
				)
			);
			update_option( 'zubquant_demo_page_id', $existing_page_id, false );
		}
	}

	/**
	 * 1-Click Local Test Seeder: Creates a sample Quantum-Sealed Vault entry + a Demo Page with [zubquant_secure_form].
	 */
	public function handle_seed_demo(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'zubquant' ) );
		}
		check_admin_referer( 'zubquant_seed_demo_nonce' );

		self::ensure_tables();

		$public_key = (string) get_option( 'zubquant_public_key', '' );
		if ( '' === $public_key ) {
			wp_safe_redirect( admin_url( 'admin.php?page=zubquant&error=no_public_key' ) );
			exit;
		}

		$this->seed_demo_data();
		$this->record_quantum_audit_event(
			'demo_vault_seeded',
			array( 'note' => 'Created sample post-quantum vault entry and demo page' )
		);

		wp_safe_redirect( admin_url( 'admin.php?page=zubquant-vault&demo_seeded=1' ) );
		exit;
	}

	/**
	 * Delete a single vault entry by ID.
	 */
	public function handle_delete_entry(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'zubquant' ) );
		}
		check_admin_referer( 'zubquant_delete_entry_nonce' );

		$entry_id = isset( $_POST['entry_id'] ) ? absint( $_POST['entry_id'] ) : 0;
		if ( $entry_id > 0 ) {
			global $wpdb;
			$wpdb->delete(
				$wpdb->prefix . 'zubquant_vault',
				array( 'id' => $entry_id ),
				array( '%d' )
			);
			$this->record_quantum_audit_event(
				'vault_entry_deleted',
				array( 'entry_id' => $entry_id )
			);
		}

		$redirect_args = array(
			'page'          => 'zubquant-vault',
			'entry_deleted' => '1',
		);
		if ( ! empty( $_POST['zq_source'] ) ) {
			$redirect_args['zq_source'] = sanitize_key( wp_unslash( $_POST['zq_source'] ) );
		}
		if ( ! empty( $_POST['zq_paged'] ) ) {
			$redirect_args['zq_paged'] = max( 1, absint( $_POST['zq_paged'] ) );
		}

		wp_safe_redirect( add_query_arg( $redirect_args, admin_url( 'admin.php' ) ) );
		exit;
	}

	/**
	 * Bulk-delete selected vault entries by ID array.
	 */
	public function handle_bulk_delete_entries(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'zubquant' ) );
		}
		check_admin_referer( 'zubquant_bulk_delete_nonce' );

		$raw_ids = isset( $_POST['zq_entry_ids'] ) && is_array( $_POST['zq_entry_ids'] )
			? array_map( 'absint', wp_unslash( $_POST['zq_entry_ids'] ) )
			: array();
		$ids     = array_values( array_filter( $raw_ids ) );

		$deleted_count = 0;
		if ( ! empty( $ids ) ) {
			global $wpdb;
			$placeholders  = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
			$deleted_count = (int) $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$wpdb->prefix}zubquant_vault WHERE id IN ({$placeholders})", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$ids
				)
			);
			$this->record_quantum_audit_event(
				'vault_entries_bulk_deleted',
				array( 'deleted_count' => $deleted_count, 'ids' => implode( ',', array_slice( $ids, 0, 25 ) ) )
			);
		}

		$redirect_args = array(
			'page'         => 'zubquant-vault',
			'bulk_deleted' => $deleted_count,
		);
		if ( ! empty( $_POST['zq_source'] ) ) {
			$redirect_args['zq_source'] = sanitize_key( wp_unslash( $_POST['zq_source'] ) );
		}
		if ( ! empty( $_POST['zq_per_page'] ) ) {
			$redirect_args['zq_per_page'] = absint( $_POST['zq_per_page'] );
		}

		wp_safe_redirect( add_query_arg( $redirect_args, admin_url( 'admin.php' ) ) );
		exit;
	}

	/**
	 * Delete all sample/demo entries (source = 'welcome_demo') from the vault in one click.
	 */
	public function handle_clear_demos(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'zubquant' ) );
		}
		check_admin_referer( 'zubquant_clear_demos_nonce' );

		global $wpdb;
		$deleted = (int) $wpdb->delete(
			$wpdb->prefix . 'zubquant_vault',
			array( 'source' => 'welcome_demo' ),
			array( '%s' )
		);

		$this->record_quantum_audit_event(
			'demo_entries_cleared',
			array( 'deleted_count' => $deleted )
		);

		wp_safe_redirect( admin_url( 'admin.php?page=zubquant-vault&demos_cleared=1' ) );
		exit;
	}

	public function handle_frontend_form_submission(): void {
		if ( ! isset( $_POST['zubquant_secure_submit'], $_POST['zubquant_form_nonce'] ) ) {
			return;
		}
		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['zubquant_form_nonce'] ) ), 'zubquant_secure_form_submit' ) ) {
			return;
		}

		self::ensure_tables();

		$subject = isset( $_POST['zq_subject'] ) ? sanitize_text_field( wp_unslash( $_POST['zq_subject'] ) ) : __( 'Secure Submission', 'zubquant' );
		$sender  = isset( $_POST['zq_sender'] ) ? sanitize_text_field( wp_unslash( $_POST['zq_sender'] ) ) : '';
		$message = isset( $_POST['zq_message'] ) ? sanitize_textarea_field( wp_unslash( $_POST['zq_message'] ) ) : '';

		$client_envelope = isset( $_POST['zq_client_envelope'] ) ? sanitize_text_field( wp_unslash( $_POST['zq_client_envelope'] ) ) : '';

		if ( str_starts_with( $client_envelope, 'zpq1.xwing-aes256gcm.' ) ) {
			global $wpdb;
			$wpdb->insert(
				$wpdb->prefix . 'zubquant_vault',
				array(
					'source'          => 'secure_form_e2ee',
					'subject'         => $subject,
					'sealed_envelope' => $client_envelope,
					'created_at'      => current_time( 'mysql', true ),
				),
				array( '%s', '%s', '%s', '%s' )
			);
		} else {
			$this->store_vault_entry(
				'secure_form',
				$subject,
				array(
					'Sender'  => $sender,
					'Subject' => $subject,
					'Message' => $message,
				)
			);
		}

		$return_url = isset( $_POST['zq_return_url'] ) ? esc_url_raw( wp_unslash( $_POST['zq_return_url'] ) ) : '';
		if ( '' === $return_url ) {
			$req_uri    = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
			$return_url = home_url( $req_uri );
		}

		wp_safe_redirect( add_query_arg( 'zq_sealed', '1', $return_url ) );
		exit;
	}

	public function render_secure_form_shortcode(): string {
		$public_key = (string) get_option( 'zubquant_public_key', '' );
		if ( '' === $public_key ) {
			return '<p>' . esc_html__( 'This secure form is being configured by the site administrator.', 'zubquant' ) . '</p>';
		}

		$js_file = ZUBQUANT_PATH . 'assets/js/zubquant.browser.js';
		$ver     = file_exists( $js_file ) ? ZUBQUANT_VERSION . '.' . (string) filemtime( $js_file ) : ZUBQUANT_VERSION;
		wp_enqueue_script(
			'zubquant-browser-sdk',
			ZUBQUANT_URL . 'assets/js/zubquant.browser.js',
			array(),
			$ver,
			true
		);

		$current_page_url = get_permalink() ? (string) get_permalink() : home_url( add_query_arg( array() ) );

		ob_start();
		if ( isset( $_GET['zq_sealed'] ) && '1' === $_GET['zq_sealed'] ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			?>
			<div style="max-width:540px;padding:14px 18px;margin-bottom:16px;background:#edfaef;border-left:4px solid #00a32a;border-radius:6px;color:#14532d;">
				<strong>✅ <?php esc_html_e( 'Message Locked & Sent!', 'zubquant' ); ?></strong><br/>
				<?php esc_html_e( 'Your message was encrypted with Post-Quantum X-Wing (ML-KEM-768 + X25519 + AES-256-GCM) and placed inside the administrator safe.', 'zubquant' ); ?>
			</div>
			<?php
		endif;
		?>
		<form method="post" action="<?php echo esc_url( $current_page_url ); ?>" class="zubquant-secure-form" data-public-key="<?php echo esc_attr( $public_key ); ?>" style="max-width:540px;padding:22px;border:1px solid #dcdcde;border-radius:10px;background:#fff;box-shadow:0 2px 6px rgba(0,0,0,0.04);">
			<?php wp_nonce_field( 'zubquant_secure_form_submit', 'zubquant_form_nonce' ); ?>
			<input type="hidden" name="zubquant_secure_submit" value="1" />
			<input type="hidden" name="zq_return_url" value="<?php echo esc_url( $current_page_url ); ?>" />
			<input type="hidden" name="zq_client_envelope" value="" />
			<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;color:#007017;font-weight:600;font-size:14px;">
				<span>🔒 <?php esc_html_e( 'End-to-End Quantum-Safe Encrypted Form', 'zubquant' ); ?></span>
			</div>
			<p>
				<label style="font-weight:500;"><?php esc_html_e( 'Your Name or Email', 'zubquant' ); ?><br/>
				<input type="text" name="zq_sender" required style="width:100%;padding:9px;margin-top:4px;border:1px solid #8c8f94;border-radius:6px;" /></label>
			</p>
			<p>
				<label style="font-weight:500;"><?php esc_html_e( 'Subject', 'zubquant' ); ?><br/>
				<input type="text" name="zq_subject" required style="width:100%;padding:9px;margin-top:4px;border:1px solid #8c8f94;border-radius:6px;" /></label>
			</p>
			<p>
				<label style="font-weight:500;"><?php esc_html_e( 'Confidential Message', 'zubquant' ); ?><br/>
				<textarea name="zq_message" rows="4" required style="width:100%;padding:9px;margin-top:4px;border:1px solid #8c8f94;border-radius:6px;"></textarea></label>
			</p>
			<button type="submit" name="zubquant_secure_submit" value="1" class="button button-primary" style="padding:6px 18px;font-size:14px;">
				<?php esc_html_e( '🔒 Lock & Send Securely', 'zubquant' ); ?>
			</button>
			<p style="margin:10px 0 0;font-size:12px;color:#646970;">
				<?php esc_html_e( 'Protected by ZubQuant Post-Quantum Encryption. Even if this website is compromised, your message stays private.', 'zubquant' ); ?>
			</p>
		</form>
		<script>
		document.addEventListener('DOMContentLoaded', function () {
			const form = document.querySelector('.zubquant-secure-form');
			if (!form) return;
			form.addEventListener('submit', async function (e) {
				const envInput = form.querySelector('input[name="zq_client_envelope"]');
				if (!window.ZubQuant || envInput.value !== '') return;
				e.preventDefault();
				const pubKey = form.getAttribute('data-public-key');
				const senderField = form.querySelector('input[name="zq_sender"]');
				const subjectField = form.querySelector('input[name="zq_subject"]');
				const msgField = form.querySelector('textarea[name="zq_message"]');
				const payload = {
					Sender: senderField.value,
					Subject: subjectField.value,
					Message: msgField.value
				};
				envInput.value = await window.ZubQuant.seal(payload, pubKey);
				senderField.value = '[Encrypted]';
				msgField.value = '[Encrypted in Browser]';
				form.submit();
			});
		});
		</script>
		<?php
		return (string) ob_get_clean();
	}

	public function render_admin_page(): void {
		self::ensure_tables();

		global $wpdb;
		$public_key         = (string) get_option( 'zubquant_public_key', '' );
		$locked_private_key = (string) get_option( 'zubquant_locked_private_key', '' );
		$verify_key         = (string) get_option( 'zubquant_audit_verify_key', '' );
		$demo_page_id       = (int) get_option( 'zubquant_demo_page_id', 0 );
		$is_configured      = '' !== $public_key;
		$show_wizard        = ! $is_configured || isset( $_GET['setup_wizard'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$has_vault_query = isset(
			$_GET['zq_source'],
			$_GET['zq_paged'],
			$_GET['zq_per_page'],
			$_GET['zq_s'],
			$_GET['demo_seeded'],
			$_GET['secret_saved'],
			$_GET['entry_deleted'],
			$_GET['bulk_deleted'],
			$_GET['demos_cleared'],
			$_GET['wc_seeded']
		) || isset( $_GET['zq_source'] ) || isset( $_GET['zq_paged'] ) || isset( $_GET['zq_per_page'] ) || isset( $_GET['zq_s'] ) || isset( $_GET['demo_seeded'] ) || isset( $_GET['secret_saved'] ) || isset( $_GET['entry_deleted'] ) || isset( $_GET['bulk_deleted'] ) || isset( $_GET['demos_cleared'] ) || isset( $_GET['wc_seeded'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$default_tab = $has_vault_query ? 'vault' : 'passwords';
		$active_tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : $default_tab; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! in_array( $active_tab, array( 'passwords', 'vault', 'audit', 'settings', 'pro' ), true ) ) {
			$active_tab = 'passwords';
		}

		$vault_table = $wpdb->prefix . 'zubquant_vault';
		$audit_table = $wpdb->prefix . 'zubquant_audit_log';

		// Vault pagination, per-page size, source filtering & server-side search
		$allowed_per_page = array( 15, 25, 50, 100 );
		$per_page_req     = isset( $_GET['zq_per_page'] ) ? absint( $_GET['zq_per_page'] ) : 15; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$per_page         = in_array( $per_page_req, $allowed_per_page, true ) ? $per_page_req : 15;
		$current_page     = isset( $_GET['zq_paged'] ) ? max( 1, absint( $_GET['zq_paged'] ) ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$source_filter    = isset( $_GET['zq_source'] ) ? sanitize_key( wp_unslash( $_GET['zq_source'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$search_query     = isset( $_GET['zq_s'] ) ? sanitize_text_field( wp_unslash( $_GET['zq_s'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$total_all_entries  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$vault_table}" );
		$demo_entries_count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$vault_table} WHERE source = %s", 'welcome_demo' ) );

		$where_clauses = array( '1=1' );
		$where_args    = array();

		if ( '' !== $source_filter ) {
			if ( 'secure_form_all' === $source_filter ) {
				$where_clauses[] = "source IN ('secure_form', 'secure_form_e2ee')";
			} elseif ( 'admin_secrets_all' === $source_filter ) {
				$where_clauses[] = "source IN ('admin_secret', 'api_key', 'client_credential')";
			} else {
				$where_clauses[] = 'source = %s';
				$where_args[]    = $source_filter;
			}
		}

		if ( '' !== $search_query ) {
			$like            = '%' . $wpdb->esc_like( ltrim( $search_query, '#' ) ) . '%';
			$id_candidate    = absint( ltrim( $search_query, '#' ) );
			$where_clauses[] = '(subject LIKE %s OR source LIKE %s OR created_at LIKE %s OR id = %d)';
			$where_args[]    = $like;
			$where_args[]    = $like;
			$where_args[]    = $like;
			$where_args[]    = $id_candidate;
		}

		$where_sql = implode( ' AND ', $where_clauses );

		if ( ! empty( $where_args ) ) {
			$total_filtered_entries = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$vault_table} WHERE {$where_sql}", $where_args ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		} else {
			$total_filtered_entries = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$vault_table} WHERE {$where_sql}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		}

		$total_pages  = max( 1, (int) ceil( $total_filtered_entries / $per_page ) );
		$current_page = min( $current_page, $total_pages );
		$offset       = ( $current_page - 1 ) * $per_page;

		$query_args   = array_merge( $where_args, array( $per_page, $offset ) );
		$entries      = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$vault_table} WHERE {$where_sql} ORDER BY id DESC LIMIT %d OFFSET %d", $query_args ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		// Audit log pagination
		$audit_per_page    = 25;
		$audit_page        = isset( $_GET['zq_audit_paged'] ) ? max( 1, absint( $_GET['zq_audit_paged'] ) ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$total_audits      = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$audit_table}" );
		$total_audit_pages = max( 1, (int) ceil( $total_audits / $audit_per_page ) );
		$audit_page        = min( $audit_page, $total_audit_pages );
		$audit_offset      = ( $audit_page - 1 ) * $audit_per_page;
		$audits            = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$audit_table} ORDER BY id DESC LIMIT %d OFFSET %d", $audit_per_page, $audit_offset ) );

		$pass_stats = $this->get_password_quantum_stats();

		$contact_url = (string) apply_filters( 'zubquant_author_contact_url', 'https://zubaer.com/contact' );
		$site_url    = (string) apply_filters( 'zubquant_author_site_url', 'https://zubaer.com/' );
		$pro_url     = (string) apply_filters( 'zubquant_pro_shop_url', 'https://www.patreon.com/Zubaer/posts/zubquant-pro-e-0-174534260' );
		$donate_url  = (string) apply_filters( 'zubquant_donate_url', 'https://www.patreon.com/cw/Zubaer/membership' );
		?>
		<style>
			.zq-wrap { max-width: 1180px; margin: 1.25rem 20px 2.5rem 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
			.zq-layout { display: grid; grid-template-columns: minmax(0, 1fr) minmax(250px, 300px); gap: 1.25rem; align-items: start; }
			@media (max-width: 960px) {
				.zq-layout { grid-template-columns: 1fr; }
			}
			@media (min-width: 961px) {
				.zq-layout__side { position: sticky; top: 46px; }
			}
			.zq-rail-card { margin: 0 0 1rem; padding: 1.1rem 1.15rem 1.15rem; border-radius: 14px; background: #fff; border: 1px solid #e2e8f0; box-shadow: 0 1px 0 rgba(15, 23, 42, 0.04); }
			.zq-rail-card--hire { background: radial-gradient(420px 160px at 100% 0%, rgba(20, 184, 166, 0.12), transparent 60%), #fff; border-color: #cce7e2; }
			.zq-rail-card__eyebrow { margin: 0 0 0.35rem; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: #0f766e; }
			.zq-rail-card__title { margin: 0 0 0.45rem; font-size: 1.05rem; line-height: 1.3; color: #0f172a; }
			.zq-rail-card__text { margin: 0 0 0.75rem; font-size: 0.88rem; line-height: 1.55; color: #475569; }
			.zq-rail-card__byline { margin: 0 0 0.85rem; font-size: 0.8rem; font-weight: 600; color: #0f766e; }
			.zq-rail-card__steps { margin: 0.55rem 0 0; padding-left: 1.15rem; font-size: 0.88rem; line-height: 1.5; color: #334155; }
			.zq-rail-card__steps li + li { margin-top: 0.35rem; }
			.zq-rail-card__actions { display: flex; flex-direction: column; align-items: flex-start; gap: 0.55rem; margin: 0; }
			.zq-rail-card__cta { background: #0f766e !important; border-color: #0f766e !important; color: #fff !important; text-shadow: none !important; box-shadow: none !important; }
			.zq-rail-card__cta:hover, .zq-rail-card__cta:focus { background: #0d9488 !important; border-color: #0d9488 !important; color: #fff !important; }
			.zq-rail-card__link { font-size: 0.82rem; font-weight: 600; color: #0f766e; text-decoration: none; }
			.zq-rail-card__link:hover { color: #0d9488; text-decoration: underline; }
			.zq-hero { background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%); color: #fff; padding: 26px 32px; border-radius: 12px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; }
			.zq-hero h1 { color: #fff; margin: 0 0 6px; font-size: 24px; font-weight: 700; }
			.zq-hero p { color: #cbd5e1; margin: 0; font-size: 14.5px; max-width: 650px; line-height: 1.5; }
			.zq-status-pill { background: rgba(16, 185, 129, 0.2); border: 1px solid #34d399; color: #ecfdf5; padding: 8px 16px; border-radius: 999px; font-weight: 600; font-size: 13px; display: inline-flex; align-items: center; gap: 8px; }
			/* 4-Tab Navigation Bar */
			.zq-tabs { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; padding: 6px; background: #e2e8f0; border-radius: 12px; }
			.zq-tab { display: inline-flex; align-items: center; gap: 8px; padding: 9px 16px; border-radius: 9px; font-size: 13.5px; font-weight: 600; color: #334155; text-decoration: none; transition: all 0.15s ease; }
			.zq-tab:hover { background: rgba(255, 255, 255, 0.65); color: #0f172a; }
			.zq-tab--active { background: #fff; color: #0f172a; box-shadow: 0 1px 3px rgba(15, 23, 42, 0.1); }
			.zq-tab__badge { font-size: 11px; font-weight: 700; padding: 2px 7px; border-radius: 999px; background: #cbd5e1; color: #1e293b; }
			.zq-tab--active .zq-tab__badge { background: #dbeafe; color: #1e40af; }
			.zq-tab__badge--warn { background: #fef2f2 !important; color: #b91c1c !important; border: 1px solid #fecaca; }
			.zq-tab__badge--ok { background: #dcfce7 !important; color: #166534 !important; }
			/* Smart Inbox Filter & Search Bar */
			.zq-inbox-toolbar { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; margin-bottom: 12px; padding: 10px 14px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; }
			.zq-pagination { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; margin-top: 14px; padding-top: 12px; border-top: 1px solid #e2e8f0; font-size: 13px; color: #475569; }
			.zq-page-links { display: inline-flex; align-items: center; gap: 4px; flex-wrap: wrap; }
			.zq-page-link { display: inline-flex; align-items: center; justify-content: center; min-width: 30px; height: 30px; padding: 0 8px; border-radius: 6px; border: 1px solid #cbd5e1; background: #fff; color: #1e293b; text-decoration: none; font-weight: 600; font-size: 12.5px; }
			.zq-page-link:hover { background: #f1f5f9; border-color: #94a3b8; color: #0f172a; }
			.zq-page-link--current { background: #2563eb; border-color: #2563eb; color: #fff !important; }
			.zq-del-btn { background: transparent; border: 1px solid transparent; border-radius: 6px; cursor: pointer; padding: 4px 7px; font-size: 13px; color: #64748b; transition: all 0.15s ease; }
			.zq-del-btn:hover { background: #fef2f2; border-color: #fecaca; color: #dc2626; }
			.zq-box { background: #fff; border: 1px solid #dcdcde; border-radius: 12px; padding: 24px 28px; margin-bottom: 22px; box-shadow: 0 1px 3px rgba(0,0,0,0.03); overflow: hidden; box-sizing: border-box; }
			.zq-box h2 { margin-top: 0; font-size: 18px; color: #1d2327; }
			.zq-metaphor { background: #f0f6fc; border-left: 4px solid #2271b1; padding: 14px 18px; border-radius: 6px; margin: 16px 0; color: #1d2327; font-size: 14px; line-height: 1.55; }
			.zq-rec-badge { background: #dff0d8; color: #1e4620; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 99px; margin-left: 6px; text-transform: uppercase; }
			.zq-unlock-bar { background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 10px; padding: 16px 20px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; margin-bottom: 14px; }
			.zq-locked-pill { display: inline-flex; align-items: center; gap: 6px; background: #fff8e5; border: 1px solid #f0c33c; color: #614200; padding: 6px 12px; border-radius: 6px; font-size: 13px; font-weight: 500; }
			details.zq-decrypted-card { background: #f0fdf4; border: 1px solid #86efac; padding: 9px 12px; border-radius: 8px; color: #14532d; font-size: 13px; line-height: 1.5; max-width: 100%; box-sizing: border-box; }
			details.zq-decrypted-card > summary { cursor: pointer; list-style: none; outline: none; display: flex; align-items: center; justify-content: space-between; gap: 10px; font-weight: 600; color: #166534; min-width: 0; }
			details.zq-decrypted-card > summary::-webkit-details-marker { display: none; }
			.zq-decrypted-preview { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 500; color: #15803d; }
			.zq-decrypted-toggle { font-size: 11px; font-weight: 600; background: #dcfce7; border: 1px solid #86efac; color: #166534; padding: 2px 8px; border-radius: 999px; white-space: nowrap; flex-shrink: 0; }
			.zq-decrypted-body { margin-top: 8px; padding-top: 8px; border-top: 1px dashed #86efac; display: flex; flex-direction: column; gap: 5px; word-break: normal; overflow-wrap: break-word; }
			.zq-decrypted-row { font-size: 13px; line-height: 1.5; color: #14532d; }
			.zq-decrypted-row strong { color: #166534; margin-right: 6px; }
			details.zq-advanced { background: #fff; border: 1px solid #e2e8f0; border-radius: 14px; padding: 18px 24px; margin-bottom: 22px; box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04); }
			details.zq-advanced > summary { font-weight: 600; font-size: 15px; cursor: pointer; color: #0f172a; outline: none; list-style: none; display: flex; align-items: center; justify-content: space-between; gap: 12px; }
			details.zq-advanced > summary::-webkit-details-marker { display: none; }
			.zq-summary-badge { font-size: 12px; font-weight: 600; color: #2563eb; background: #eff6ff; border: 1px solid #bfdbfe; padding: 4px 10px; border-radius: 999px; white-space: nowrap; }
			/* Educational & Animated Infographic Styles */
			.zq-edu-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; margin-top: 16px; }
			@media (max-width: 720px) {
				.zq-edu-grid { grid-template-columns: 1fr; }
			}
			.zq-edu-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 20px; }
			.zq-edu-card h4 { margin: 0 0 8px; font-size: 15px; color: #0f172a; display: flex; align-items: center; gap: 8px; }
			.zq-edu-card p { margin: 0; font-size: 13.5px; color: #475569; line-height: 1.6; }
			.zq-edu-card.zq-danger { background: linear-gradient(180deg, #fff5f5 0%, #fef2f2 100%); border-color: #fecaca; }
			.zq-edu-card.zq-danger h4 { color: #991b1b; }
			.zq-edu-card.zq-safe { grid-column: 1 / -1; background: linear-gradient(135deg, #f0fdf4 0%, #ecfdf5 100%); border-color: #86efac; display: flex; flex-direction: column; gap: 10px; }
			.zq-edu-card.zq-safe h4 { color: #166534; font-size: 15.5px; margin: 0; }
			.zq-safe-pillars { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-top: 2px; }
			@media (max-width: 720px) {
				.zq-safe-pillars { grid-template-columns: 1fr; }
			}
			.zq-safe-pillar { background: rgba(255, 255, 255, 0.75); border: 1px solid #bbf7d0; border-radius: 8px; padding: 12px 14px; font-size: 13px; color: #14532d; line-height: 1.5; }
			.zq-safe-pillar strong { display: block; color: #166534; margin-bottom: 3px; font-size: 13.5px; }
			.zq-flow-wrap { background: linear-gradient(180deg, #0f172a 0%, #1e293b 100%); border-radius: 12px; padding: 22px; margin: 18px 0 6px; color: #f8fafc; overflow-x: auto; }
			.zq-flow-title { text-align: center; font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em; color: #94a3b8; margin-bottom: 12px; font-weight: 600; }
			@keyframes zqDashFlow {
				to { stroke-dashoffset: -48; }
			}
			@keyframes zqPulseGlow {
				0%, 100% { filter: drop-shadow(0 0 4px rgba(52, 211, 153, 0.35)); }
				50% { filter: drop-shadow(0 0 12px rgba(52, 211, 153, 0.85)); }
			}
			@keyframes zqPulseRed {
				0%, 100% { opacity: 0.75; }
				50% { opacity: 1; }
			}
			.zq-anim-line { stroke-dasharray: 8 6; animation: zqDashFlow 1.6s linear infinite; }
			.zq-anim-shield { animation: zqPulseGlow 2.8s ease-in-out infinite; }
			.zq-anim-block { animation: zqPulseRed 2.2s ease-in-out infinite; }
			.zq-shortcode-badge {
				display: inline-flex;
				align-items: center;
				gap: 7px;
				margin: 6px 0 4px;
				padding: 6px 10px;
				background: linear-gradient(135deg, #eff6ff 0%, #e0f2fe 100%);
				border: 1.5px dashed #2563eb;
				border-radius: 7px;
				color: #1e40af;
				font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
				font-size: 12.5px;
				font-weight: 700;
				cursor: pointer;
				transition: all 0.15s ease;
				box-shadow: 0 1px 2px rgba(37, 99, 235, 0.08);
			}
			.zq-shortcode-badge:hover {
				background: #dbeafe;
				border-color: #1d4ed8;
				transform: translateY(-1px);
			}
			.zq-shortcode-badge__hint {
				font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
				font-size: 10.5px;
				font-weight: 600;
				background: #2563eb;
				color: #fff;
				padding: 2px 6px;
				border-radius: 4px;
				letter-spacing: 0.02em;
			}
		</style>

		<div class="zq-wrap">
			<!-- Always keep hidden key references in DOM so JS unlock/verify works on every tab -->
			<input type="hidden" id="zq-public-key-ref" value="<?php echo esc_attr( $public_key ); ?>" />
			<input type="hidden" id="zq-locked-private-key-ref" value="<?php echo esc_attr( $locked_private_key ); ?>" />
			<input type="hidden" id="zq-audit-verify-key-ref" value="<?php echo esc_attr( $verify_key ); ?>" />

			<div class="zq-hero">
				<div>
					<h1>🛡️ <?php esc_html_e( 'ZubQuant Safe — Quantum-Proof Website Protection', 'zubquant' ); ?></h1>
					<p><?php esc_html_e( 'Protects your confidential form entries, customer details, and admin security logs so that even if your database is hacked, nobody can read your data without your Master Password.', 'zubquant' ); ?></p>
				</div>
				<div>
					<?php if ( $is_configured ) : ?>
						<span class="zq-status-pill">🟢 <?php esc_html_e( 'Quantum Shield Active', 'zubquant' ); ?></span>
					<?php else : ?>
						<span class="zq-status-pill" style="background:rgba(245,158,11,0.25);border-color:#fbbf24;">⚡ <?php esc_html_e( '1-Minute Setup Required', 'zubquant' ); ?></span>
					<?php endif; ?>
				</div>
			</div>

			<?php if ( ! $show_wizard ) : ?>
				<!-- 4-TAB NAVIGATION BAR (SYNCED WITH WP ADMIN SUBMENU PAGES) -->
				<nav class="zq-tabs" aria-label="<?php esc_attr_e( 'ZubQuant Sections', 'zubquant' ); ?>">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=zubquant' ) ); ?>" class="zq-tab <?php echo 'passwords' === $active_tab ? 'zq-tab--active' : ''; ?>">
						<span>🔑 <?php esc_html_e( 'Password & Login Shield', 'zubquant' ); ?></span>
						<?php if ( $pass_stats['legacy_md5'] > 0 ) : ?>
							<span class="zq-tab__badge zq-tab__badge--warn"><?php echo esc_html( (string) $pass_stats['legacy_md5'] . ' Weak MD5' ); ?></span>
						<?php else : ?>
							<span class="zq-tab__badge zq-tab__badge--ok"><?php echo esc_html( (string) $pass_stats['quantum_hardened'] . '/' . (string) $pass_stats['total'] ); ?></span>
						<?php endif; ?>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=zubquant-vault' ) ); ?>" class="zq-tab <?php echo 'vault' === $active_tab ? 'zq-tab--active' : ''; ?>">
						<span>📬 <?php esc_html_e( 'Vault & Messages', 'zubquant' ); ?></span>
						<span class="zq-tab__badge"><?php echo esc_html( (string) $total_all_entries ); ?></span>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=zubquant-audit' ) ); ?>" class="zq-tab <?php echo 'audit' === $active_tab ? 'zq-tab--active' : ''; ?>">
						<span>🛡️ <?php esc_html_e( 'Security Audit Log', 'zubquant' ); ?></span>
						<span class="zq-tab__badge"><?php echo esc_html( (string) $total_audits ); ?></span>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=zubquant-settings' ) ); ?>" class="zq-tab <?php echo 'settings' === $active_tab ? 'zq-tab--active' : ''; ?>">
						<span>⚙️ <?php esc_html_e( 'Guide & Key Settings', 'zubquant' ); ?></span>
					</a>
					<?php do_action( 'zubquant_admin_tabs', $active_tab, $this ); ?>
				</nav>
			<?php endif; ?>

			<?php if ( isset( $_GET['onboarded'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="zq-box" style="background:linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%);border:2px solid #f59e0b;margin-bottom:22px;">
					<h2 style="color:#92400e;margin:0 0 8px;display:flex;align-items:center;gap:8px;">
						📌 <?php esc_html_e( 'Setup Complete! Please Store These 2 Items Securely Right Now', 'zubquant' ); ?>
					</h2>
					<p style="margin:0 0 14px;color:#78350f;font-size:14px;line-height:1.55;">
						<?php esc_html_e( 'Because ZubQuant uses true Zero-Knowledge encryption, there is NO "Forgot Password" reset link on the server. To ensure you never lose access to your messages in the future, store these two items in a safe place (such as 1Password, Bitwarden, Apple/Google Passwords, or an offline USB drive):', 'zubquant' ); ?>
					</p>
					<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(260px, 1fr));gap:12px;margin-bottom:14px;">
						<div style="background:#fff;border:1px solid #fcd34d;border-radius:8px;padding:12px 14px;">
							<strong style="color:#92400e;display:block;margin-bottom:4px;">1️⃣ <?php esc_html_e( 'Your Master Safe Password', 'zubquant' ); ?></strong>
							<span style="font-size:13px;color:#57534e;"><?php esc_html_e( 'Used for everyday 1-click unlocking inside WordPress. Save it in your browser Password Manager.', 'zubquant' ); ?></span>
						</div>
						<div style="background:#fff;border:1px solid #fcd34d;border-radius:8px;padding:12px 14px;">
							<strong style="color:#92400e;display:block;margin-bottom:4px;">2️⃣ <?php esc_html_e( 'Your Emergency Recovery Kit (zubquant-recovery-kit.txt)', 'zubquant' ); ?></strong>
							<span style="font-size:13px;color:#57534e;"><?php esc_html_e( 'Contains your offline Emergency Recovery Key (zpq1_sec_...). Keep it private—never upload it to your public web server.', 'zubquant' ); ?></span>
						</div>
					</div>
					<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
						<button type="button" class="button button-primary" id="zq-redownload-kit-btn">
							⬇️ <?php esc_html_e( 'Download Emergency Recovery Kit (.txt) Again', 'zubquant' ); ?>
						</button>
						<button type="button" class="button" id="zq-copy-emergency-key-btn">
							📋 <?php esc_html_e( 'Copy Emergency Recovery Key to Clipboard', 'zubquant' ); ?>
						</button>
					</div>
				</div>
			<?php endif; ?>

			<div class="zq-layout">
				<div class="zq-layout__main">
			<?php if ( $show_wizard ) : ?>
				<!-- STEP-BY-STEP EASY ONBOARDING WIZARD FOR NON-TECHNICAL USERS -->
				<div class="zq-box">
					<h2>✨ <?php esc_html_e( 'Quick 60-Second Setup (Recommended Configuration)', 'zubquant' ); ?></h2>
					<div class="zq-metaphor">
						<strong>💡 <?php esc_html_e( 'How does ZubQuant work in plain English?', 'zubquant' ); ?></strong><br/>
						<?php esc_html_e( 'Think of ZubQuant like a steel drop-box safe in your office. Visitors and forms on your website can drop confidential messages INTO the slot anytime—but WordPress itself does not have the key to open the safe door. Only YOUR Master Password unlocks the messages right inside your browser.', 'zubquant' ); ?>
					</div>

					<form id="zq-wizard-form" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<input type="hidden" name="action" value="zubquant_save_keys" />
						<input type="hidden" name="zubquant_public_key" id="zq-wiz-public-key" value="" />
						<input type="hidden" name="zubquant_locked_private_key" id="zq-wiz-locked-key" value="" />
						<?php wp_nonce_field( 'zubquant_save_keys_nonce' ); ?>

						<h3 style="margin-top:20px;">1. <?php esc_html_e( 'Choose Your Master Safe Password', 'zubquant' ); ?></h3>
						<p style="color:#50575e;margin-top:0;"><?php esc_html_e( 'You will use this password whenever you want to unlock and read protected messages in WordPress.', 'zubquant' ); ?></p>
						<div style="display:flex;gap:14px;flex-wrap:wrap;max-width:680px;">
							<div style="flex:1;min-width:260px;">
								<label style="font-weight:600;display:block;margin-bottom:4px;"><?php esc_html_e( 'Master Safe Password', 'zubquant' ); ?></label>
								<input type="password" id="zq-wiz-pass1" required minlength="6" placeholder="<?php esc_attr_e( 'At least 6 characters...', 'zubquant' ); ?>" style="width:100%;padding:8px;" />
							</div>
							<div style="flex:1;min-width:260px;">
								<label style="font-weight:600;display:block;margin-bottom:4px;"><?php esc_html_e( 'Confirm Master Password', 'zubquant' ); ?></label>
								<input type="password" id="zq-wiz-pass2" required minlength="6" placeholder="<?php esc_attr_e( 'Re-type password...', 'zubquant' ); ?>" style="width:100%;padding:8px;" />
							</div>
						</div>

						<div style="max-width:680px;margin-top:12px;padding:12px 16px;background:#fff8e5;border-left:4px solid #f59e0b;border-radius:6px;font-size:13px;color:#78350f;line-height:1.5;">
							<strong>⚠️ <?php esc_html_e( 'Important — Please Store Your Password & Recovery Kit Securely:', 'zubquant' ); ?></strong><br/>
							<?php esc_html_e( 'Because ZubQuant is 100% Zero-Knowledge, your password is never sent to our servers or stored in WordPress. If you forget your Master Password, the ONLY way to unlock your data is with the Emergency Recovery Kit (.txt) that downloads when you click Activate below. Please store both in a Password Manager (like 1Password, Bitwarden, or Apple/Google Passwords).', 'zubquant' ); ?>
						</div>

						<h3 style="margin-top:24px;">2. <?php esc_html_e( 'Recommended Protection Settings', 'zubquant' ); ?></h3>
						<p style="margin:8px 0;">
							<label>
								<input type="checkbox" checked disabled />
								<strong><?php esc_html_e( 'Enable Hybrid Post-Quantum Encryption for Forms & Vault', 'zubquant' ); ?></strong>
								<span class="zq-rec-badge"><?php esc_html_e( 'Recommended', 'zubquant' ); ?></span>
							</label>
						</p>
						<p style="margin:8px 0;">
							<label>
								<input type="checkbox" checked disabled />
								<strong><?php esc_html_e( 'Enable Tamper-Proof Admin Activity & Login Log', 'zubquant' ); ?></strong>
								<span class="zq-rec-badge"><?php esc_html_e( 'Recommended', 'zubquant' ); ?></span>
							</label>
						</p>
						<p style="margin:8px 0;">
							<label>
								<input type="checkbox" name="zubquant_onboarding_seed" value="1" checked />
								<strong><?php esc_html_e( 'Create a ready-to-use "Send a Confidential Message" page & sample welcome entry', 'zubquant' ); ?></strong>
								<span class="zq-rec-badge"><?php esc_html_e( 'Recommended', 'zubquant' ); ?></span>
							</label>
						</p>
						<p style="margin:8px 0 18px;">
							<label>
								<input type="checkbox" id="zq-wiz-download-kit" checked />
								<strong><?php esc_html_e( 'Automatically download my Emergency Recovery Kit (.txt) in case I ever forget my password', 'zubquant' ); ?></strong>
								<span class="zq-rec-badge"><?php esc_html_e( 'Recommended', 'zubquant' ); ?></span>
							</label>
						</p>

						<!-- COLLAPSIBLE ADVANCED SETUP OPTIONS FOR DEVELOPERS & SECURITY AUDITORS -->
						<details class="zq-advanced" style="margin:0 0 22px;background:#f8fafc;border:1px solid #cbd5e1;padding:14px 18px;border-radius:10px;">
							<summary style="font-size:14px;">
								<span>⚙️ <?php esc_html_e( 'Advanced Setup Options (Restore Recovery Key, Air-Gapped Mode, or Custom CLI Keys)', 'zubquant' ); ?></span>
								<span class="zq-summary-badge"><?php esc_html_e( 'Optional — For Advanced Users ▾', 'zubquant' ); ?></span>
							</summary>
							<div style="margin-top:14px;padding-top:12px;border-top:1px solid #e2e8f0;font-size:13.5px;color:#334155;">
								<p style="margin:0 0 12px;color:#475569;">
									<?php esc_html_e( 'Most users do not need to change anything here. Use these options if you are migrating an existing safe, restoring from your Emergency Recovery Kit, or running a strict air-gapped server.', 'zubquant' ); ?>
								</p>

								<div style="display:flex;flex-direction:column;gap:12px;">
									<label style="display:block;background:#fff;border:1px solid #cbd5e1;border-radius:8px;padding:12px 14px;cursor:pointer;">
										<input type="radio" name="zq_wiz_mode" value="generate" checked />
										<strong><?php esc_html_e( 'Standard Mode (Default): Generate a brand-new X-Wing (ML-KEM-768 + X25519) keypair in browser', 'zubquant' ); ?></strong>
										<span class="zq-rec-badge"><?php esc_html_e( 'Recommended', 'zubquant' ); ?></span>
									</label>

									<div style="background:#fff;border:1px solid #cbd5e1;border-radius:8px;padding:12px 14px;">
										<label style="display:block;cursor:pointer;">
											<input type="radio" name="zq_wiz_mode" value="restore" />
											<strong><?php esc_html_e( 'Restore / Migrate Mode: Import an existing Emergency Recovery Key (zpq1_sec_...)', 'zubquant' ); ?></strong>
										</label>
										<div id="zq-wiz-restore-box" style="display:none;margin-top:10px;padding-left:22px;">
											<label style="display:block;font-weight:600;margin-bottom:4px;"><?php esc_html_e( 'Paste Existing Emergency Private Key (zpq1_sec_...):', 'zubquant' ); ?></label>
											<input type="text" id="zq-wiz-restore-sec" placeholder="zpq1_sec_..." class="large-text code" style="width:100%;max-width:600px;" />
											<p style="margin:4px 0 0;font-size:12px;color:#64748b;">
												<?php esc_html_e( 'ZubQuant will automatically derive the matching Public Key (zpq1_pub_...) and lock the vault using the Master Safe Password you entered in Step 1.', 'zubquant' ); ?>
											</p>
										</div>
									</div>

									<div style="background:#fff;border:1px solid #cbd5e1;border-radius:8px;padding:12px 14px;">
										<label style="display:block;cursor:pointer;">
											<input type="radio" name="zq_wiz_mode" value="custom_pub" />
											<strong><?php esc_html_e( 'CLI / Air-Gapped Public-Key-Only Mode: Bring your own Public Encapsulation Key (zpq1_pub_...)', 'zubquant' ); ?></strong>
										</label>
										<div id="zq-wiz-custom-pub-box" style="display:none;margin-top:10px;padding-left:22px;">
											<label style="display:block;font-weight:600;margin-bottom:4px;"><?php esc_html_e( 'Public Encapsulation Key (zpq1_pub_...):', 'zubquant' ); ?></label>
											<input type="text" id="zq-wiz-custom-pub" placeholder="zpq1_pub_..." class="large-text code" style="width:100%;max-width:600px;margin-bottom:8px;" />
											<label style="display:block;font-weight:600;margin-bottom:4px;"><?php esc_html_e( 'Optional PBKDF2 Locked Private Key Vault (leave blank for pure Air-Gapped Server):', 'zubquant' ); ?></label>
											<input type="text" id="zq-wiz-custom-vault" placeholder="zpq1.vault.pbkdf2-sha256... (optional)" class="large-text code" style="width:100%;max-width:600px;" />
											<p style="margin:4px 0 0;font-size:12px;color:#64748b;">
												<?php esc_html_e( 'In this mode, Step 1 Master Password is not required. You will unlock messages by pasting your offline zpq1_sec_... key.', 'zubquant' ); ?>
											</p>
										</div>
									</div>

									<div id="zq-wiz-airgap-row" style="padding:8px 12px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;">
										<label style="cursor:pointer;">
											<input type="checkbox" id="zq-wiz-airgap-only" />
											<strong>🔒 <?php esc_html_e( 'Strict Air-Gapped Storage:', 'zubquant' ); ?></strong>
											<?php esc_html_e( 'Do NOT store even the password-locked private key in WordPress (only save the Public Key on the server; I will unlock messages using my downloaded Recovery Kit).', 'zubquant' ); ?>
										</label>
									</div>
								</div>
							</div>
						</details>

						<button type="submit" id="zq-wiz-submit-btn" class="button button-primary button-hero">
							🛡️ <?php esc_html_e( 'Activate Quantum Protection Now (Recommended)', 'zubquant' ); ?>
						</button>
						<?php if ( $is_configured ) : ?>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=zubquant' ) ); ?>" class="button button-large" style="margin-left:10px;line-height:44px;">
								<?php esc_html_e( 'Cancel', 'zubquant' ); ?>
							</a>
						<?php endif; ?>
					</form>
				</div>
			<?php elseif ( 'vault' === $active_tab ) : ?>
				<!-- TAB 1: VAULT & MESSAGES (DEFAULT INBOX) -->
				<div class="zq-box">
					<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:12px;">
						<h2 style="margin:0;">📬 <?php esc_html_e( 'Protected Messages, Form Submissions & Admin Secrets', 'zubquant' ); ?></h2>
						<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
							<button type="button" class="button button-primary" id="zq-toggle-secret-form-btn">
								🔐 <?php esc_html_e( '+ Lock Secret Note / API Key', 'zubquant' ); ?>
							</button>
							<?php if ( $demo_page_id > 0 && get_post( $demo_page_id ) ) : ?>
								<a href="<?php echo esc_url( (string) get_permalink( $demo_page_id ) ); ?>" target="_blank" class="button">
									<?php esc_html_e( 'Open Secure Contact Form Page ↗', 'zubquant' ); ?>
								</a>
							<?php endif; ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;margin:0;">
								<input type="hidden" name="action" value="zubquant_seed_demo" />
								<?php wp_nonce_field( 'zubquant_seed_demo_nonce' ); ?>
								<button type="submit" class="button"><?php esc_html_e( '+ Sample Test Entry', 'zubquant' ); ?></button>
							</form>
							<?php if ( $demo_entries_count > 0 ) : ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;margin:0;" onsubmit="return window.confirm('Clear all sample welcome_demo test entries?');">
									<input type="hidden" name="action" value="zubquant_clear_demos" />
									<?php wp_nonce_field( 'zubquant_clear_demos_nonce' ); ?>
									<button type="submit" class="button" title="<?php esc_attr_e( 'Remove all welcome_demo test entries in one click', 'zubquant' ); ?>">
										🧹 <?php echo esc_html( sprintf( __( 'Clear Demo Entries (%d)', 'zubquant' ), $demo_entries_count ) ); ?>
									</button>
								</form>
							<?php endif; ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;margin:0;">
								<input type="hidden" name="action" value="zubquant_export_vault" />
								<?php wp_nonce_field( 'zubquant_export_vault_nonce' ); ?>
								<button type="submit" class="button" title="<?php esc_attr_e( 'Download an offline JSON backup of your quantum-sealed vault capsules and signed audit log', 'zubquant' ); ?>">
									⬇️ <?php esc_html_e( 'Export Backup (.json)', 'zubquant' ); ?>
								</button>
							</form>
						</div>
					</div>

					<!-- ACTIVE SITE-WIDE AUTO-PROTECTION STATUS STRIP -->
					<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:14px;padding:10px 14px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;font-size:12.5px;color:#166534;">
						<strong>🛡️ <?php esc_html_e( 'Active Site-Wide Protections:', 'zubquant' ); ?></strong>
						<span style="background:#fff;border:1px solid #86efac;padding:2px 8px;border-radius:999px;">✓ <?php esc_html_e( 'Auto-Form Shield (CF7, WPForms, Elementor, Ninja, Fluent)', 'zubquant' ); ?></span>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=zubquant' ) ); ?>" style="background:#fff;border:1px solid #86efac;padding:2px 8px;border-radius:999px;color:#166534;text-decoration:none;font-weight:600;">✓ <?php esc_html_e( 'SHA3-512 + Argon2id Password Shield →', 'zubquant' ); ?></a>
						<span style="background:#fff;border:1px solid #86efac;padding:2px 8px;border-radius:999px;">✓ <?php esc_html_e( '[zubquant_secure_form]', 'zubquant' ); ?></span>
						<span style="background:#fff;border:1px solid #86efac;padding:2px 8px;border-radius:999px;">✓ <?php esc_html_e( 'Admin Secret Vault', 'zubquant' ); ?></span>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=zubquant-audit' ) ); ?>" style="background:#fff;border:1px solid #86efac;padding:2px 8px;border-radius:999px;color:#166534;text-decoration:none;font-weight:600;">✓ <?php esc_html_e( 'ML-DSA-65 Intrusion & Audit Log →', 'zubquant' ); ?></a>
					</div>

					<?php if ( isset( $_GET['entry_deleted'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
						<div style="margin-bottom:12px;padding:9px 14px;background:#f0fdf4;border:1px solid #86efac;border-radius:8px;color:#166534;font-size:13px;font-weight:600;">
							✅ <?php esc_html_e( 'Vault entry deleted.', 'zubquant' ); ?>
						</div>
					<?php elseif ( isset( $_GET['bulk_deleted'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
						<div style="margin-bottom:12px;padding:9px 14px;background:#f0fdf4;border:1px solid #86efac;border-radius:8px;color:#166534;font-size:13px;font-weight:600;">
							✅ <?php echo esc_html( sprintf( __( 'Deleted %d selected vault entries.', 'zubquant' ), absint( $_GET['bulk_deleted'] ) ) ); ?>
						</div>
					<?php elseif ( isset( $_GET['demos_cleared'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
						<div style="margin-bottom:12px;padding:9px 14px;background:#f0fdf4;border:1px solid #86efac;border-radius:8px;color:#166534;font-size:13px;font-weight:600;">
							✅ <?php esc_html_e( 'Sample welcome_demo entries cleared from your vault.', 'zubquant' ); ?>
						</div>
					<?php endif; ?>

					<!-- INLINE DRAWER TO LOCK AN ADMIN SECRET NOTE / API KEY / CREDENTIAL -->
					<div id="zq-secret-form-drawer" style="display:none;margin-bottom:16px;padding:16px 20px;background:#eff6ff;border:1.5px solid #93c5fd;border-radius:10px;">
						<h3 style="margin:0 0 8px;font-size:15px;color:#1e3a8a;">🔐 <?php esc_html_e( 'Seal a Confidential Admin Note, API Key, or Client Credential into Your Quantum Safe', 'zubquant' ); ?></h3>
						<p style="margin:0 0 12px;font-size:13px;color:#334155;">
							<?php esc_html_e( 'Anything you enter below is immediately encapsulated with your X-Wing (ML-KEM-768 + X25519 + AES-256-GCM) Public Key so nobody can read it in MySQL without your Master Safe Password.', 'zubquant' ); ?>
						</p>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
							<input type="hidden" name="action" value="zubquant_add_secret" />
							<?php wp_nonce_field( 'zubquant_add_secret_nonce' ); ?>
							<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:10px;">
								<div style="flex:2;min-width:240px;">
									<label style="display:block;font-weight:600;margin-bottom:4px;font-size:12.5px;"><?php esc_html_e( 'Title / Label', 'zubquant' ); ?></label>
									<input type="text" name="zubquant_secret_title" required placeholder="<?php esc_attr_e( 'e.g., Production Stripe API Key or Server Recovery Codes', 'zubquant' ); ?>" style="width:100%;padding:6px 10px;" />
								</div>
								<div style="flex:1;min-width:180px;">
									<label style="display:block;font-weight:600;margin-bottom:4px;font-size:12.5px;"><?php esc_html_e( 'Category', 'zubquant' ); ?></label>
									<select name="zubquant_secret_category" style="width:100%;padding:6px 10px;">
										<option value="admin_secret"><?php esc_html_e( 'Admin Secret Note', 'zubquant' ); ?></option>
										<option value="api_key"><?php esc_html_e( 'API Key / Token', 'zubquant' ); ?></option>
										<option value="client_credential"><?php esc_html_e( 'Client Credential', 'zubquant' ); ?></option>
									</select>
								</div>
							</div>
							<div style="margin-bottom:12px;">
								<label style="display:block;font-weight:600;margin-bottom:4px;font-size:12.5px;"><?php esc_html_e( 'Confidential Content / Secret Value', 'zubquant' ); ?></label>
								<textarea name="zubquant_secret_body" rows="3" required placeholder="<?php esc_attr_e( 'Paste secret key, credentials, or confidential note...', 'zubquant' ); ?>" style="width:100%;padding:8px 10px;"></textarea>
							</div>
							<button type="submit" class="button button-primary">🔒 <?php esc_html_e( 'Seal into Quantum Safe', 'zubquant' ); ?></button>
							<button type="button" class="button" id="zq-cancel-secret-form-btn" style="margin-left:6px;"><?php esc_html_e( 'Cancel', 'zubquant' ); ?></button>
						</form>
					</div>

					<!-- 1-CLICK UNLOCK BAR -->
					<div class="zq-unlock-bar">
						<div id="zq-safe-status-label">
							<strong>🔒 <?php esc_html_e( 'Safe is Currently Locked', 'zubquant' ); ?></strong>
							<span style="color:#646970;font-size:13px;margin-left:6px;"><?php esc_html_e( 'Enter your Master Safe Password to read messages.', 'zubquant' ); ?></span>
						</div>
						<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;" id="zq-unlock-controls">
							<input type="password" id="zq-unlock-passphrase" placeholder="<?php esc_attr_e( 'Master Safe Password...', 'zubquant' ); ?>" style="min-width:200px;padding:6px 10px;" />
							<button type="button" class="button button-primary" id="zq-decrypt-all-btn">
								🔓 <?php esc_html_e( 'Unlock Safe', 'zubquant' ); ?>
							</button>
							<button type="button" class="button" id="zq-lock-now-btn" style="display:none;">
								🔒 <?php esc_html_e( 'Lock Safe', 'zubquant' ); ?>
							</button>
							<button type="button" class="button" id="zq-export-recovery-btn" style="display:none;" title="<?php esc_attr_e( 'Download a fresh copy of your Emergency Recovery Kit (.txt)', 'zubquant' ); ?>">
								🔑 <?php esc_html_e( 'Save Recovery Kit', 'zubquant' ); ?>
							</button>
							<label style="font-size:12.5px;color:#50575e;margin-left:4px;">
								<input type="checkbox" id="zq-remember-session" checked />
								<?php esc_html_e( 'Keep unlocked while this tab is open', 'zubquant' ); ?>
							</label>
						</div>
					</div>

					<!-- SMART INBOX FILTER, PAGE SIZE & HYBRID SEARCH TOOLBAR -->
					<form method="get" action="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>" class="zq-inbox-toolbar">
						<input type="hidden" name="page" value="zubquant-vault" />
						<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
							<select name="zq_source" id="zq-source-select" onchange="this.form.submit()" style="font-size:13px;padding:4px 26px 4px 10px;max-width:220px;">
								<option value="" <?php selected( $source_filter, '' ); ?>><?php echo esc_html( sprintf( __( 'All Sources (%d)', 'zubquant' ), $total_all_entries ) ); ?></option>
								<option value="secure_form_all" <?php selected( $source_filter, 'secure_form_all' ); ?>><?php esc_html_e( 'Secure Contact Form ([zubquant_secure_form])', 'zubquant' ); ?></option>
								<option value="admin_secrets_all" <?php selected( $source_filter, 'admin_secrets_all' ); ?>><?php esc_html_e( 'Admin Secret Notes & API Keys', 'zubquant' ); ?></option>
								<option value="contact_form_7" <?php selected( $source_filter, 'contact_form_7' ); ?>><?php esc_html_e( 'Contact Form 7', 'zubquant' ); ?></option>
								<option value="wpforms" <?php selected( $source_filter, 'wpforms' ); ?>><?php esc_html_e( 'WPForms', 'zubquant' ); ?></option>
								<option value="elementor_forms" <?php selected( $source_filter, 'elementor_forms' ); ?>><?php esc_html_e( 'Elementor Forms', 'zubquant' ); ?></option>
								<option value="ninja_forms" <?php selected( $source_filter, 'ninja_forms' ); ?>><?php esc_html_e( 'Ninja Forms', 'zubquant' ); ?></option>
								<option value="fluent_forms" <?php selected( $source_filter, 'fluent_forms' ); ?>><?php esc_html_e( 'Fluent Forms', 'zubquant' ); ?></option>
								<option value="woocommerce_order" <?php selected( $source_filter, 'woocommerce_order' ); ?>><?php esc_html_e( 'WooCommerce Orders (Pro)', 'zubquant' ); ?></option>
								<option value="encrypted_file_drop" <?php selected( $source_filter, 'encrypted_file_drop' ); ?>><?php esc_html_e( 'Encrypted File Drop-Box (Pro)', 'zubquant' ); ?></option>
								<option value="welcome_demo" <?php selected( $source_filter, 'welcome_demo' ); ?>><?php esc_html_e( 'Sample Demo Entries (welcome_demo)', 'zubquant' ); ?></option>
							</select>

							<select name="zq_per_page" onchange="this.form.submit()" title="<?php esc_attr_e( 'Messages per page', 'zubquant' ); ?>" style="font-size:13px;padding:4px 24px 4px 8px;">
								<option value="15" <?php selected( $per_page, 15 ); ?>><?php esc_html_e( '15 / page', 'zubquant' ); ?></option>
								<option value="25" <?php selected( $per_page, 25 ); ?>><?php esc_html_e( '25 / page', 'zubquant' ); ?></option>
								<option value="50" <?php selected( $per_page, 50 ); ?>><?php esc_html_e( '50 / page', 'zubquant' ); ?></option>
								<option value="100" <?php selected( $per_page, 100 ); ?>><?php esc_html_e( '100 / page', 'zubquant' ); ?></option>
							</select>

							<button type="button" class="button button-small" id="zq-bulk-delete-trigger-btn" style="display:none;color:#dc2626;border-color:#fca5a5;background:#fef2f2;">
								🗑️ <span id="zq-bulk-delete-label"><?php esc_html_e( 'Delete Selected', 'zubquant' ); ?></span>
							</button>

							<?php if ( '' !== $source_filter || '' !== $search_query ) : ?>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=zubquant-vault' ) ); ?>" class="button button-small"><?php esc_html_e( 'Reset', 'zubquant' ); ?></a>
							<?php endif; ?>
						</div>

						<div style="display:flex;align-items:center;gap:6px;flex:1;min-width:220px;max-width:340px;">
							<input type="search" name="zq_s" id="zq-vault-search" value="<?php echo esc_attr( $search_query ); ?>" placeholder="<?php esc_attr_e( '🔍 Search subject, ID, or unlocked text...', 'zubquant' ); ?>" style="width:100%;padding:5px 10px;font-size:13px;border:1px solid #cbd5e1;border-radius:6px;" />
							<button type="submit" class="button button-small"><?php esc_html_e( 'Search DB', 'zubquant' ); ?></button>
						</div>
					</form>

					<!-- HIDDEN BULK DELETE FORM -->
					<form id="zq-bulk-delete-form" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:none;">
						<input type="hidden" name="action" value="zubquant_bulk_delete_entries" />
						<input type="hidden" name="zq_source" value="<?php echo esc_attr( $source_filter ); ?>" />
						<input type="hidden" name="zq_per_page" value="<?php echo esc_attr( (string) $per_page ); ?>" />
						<?php wp_nonce_field( 'zubquant_bulk_delete_nonce' ); ?>
						<div id="zq-bulk-delete-inputs"></div>
					</form>

					<table class="widefat striped" id="zq-vault-table" style="border-radius:8px;overflow:hidden;table-layout:fixed;width:100%;box-sizing:border-box;">
						<thead>
							<tr>
								<th style="width:32px;text-align:center;padding:8px 4px;">
									<input type="checkbox" id="zq-select-all-rows" title="<?php esc_attr_e( 'Select all on this page', 'zubquant' ); ?>" style="margin:0;" />
								</th>
								<th style="width:185px;"><?php esc_html_e( 'Entry & Subject', 'zubquant' ); ?></th>
								<th><?php esc_html_e( 'Protected Message Content', 'zubquant' ); ?></th>
								<th style="width:44px;text-align:center;padding:8px 4px;"><?php esc_html_e( 'Del', 'zubquant' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php if ( empty( $entries ) ) : ?>
								<tr><td colspan="4"><?php esc_html_e( 'No messages match this view yet. Click "+ Sample Test Entry" above or submit a form to test!', 'zubquant' ); ?></td></tr>
							<?php else : ?>
								<?php foreach ( $entries as $row ) : ?>
									<tr class="zq-vault-row">
										<td style="text-align:center;vertical-align:top;padding:10px 4px;">
											<input type="checkbox" class="zq-row-checkbox" value="<?php echo esc_attr( (string) $row->id ); ?>" style="margin:2px 0 0;" />
										</td>
										<td style="vertical-align:top;word-break:break-word;">
											<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:3px;">
												<strong style="color:#0f172a;">#<?php echo esc_html( (string) $row->id ); ?></strong>
												<code style="font-size:11px;padding:1px 5px;background:#f1f5f9;border-radius:4px;"><?php echo esc_html( (string) $row->source ); ?></code>
											</div>
											<div style="font-weight:600;color:#1e293b;font-size:13px;line-height:1.35;margin-bottom:3px;">
												<?php echo esc_html( (string) $row->subject ); ?>
											</div>
											<div style="font-size:11px;color:#64748b;">
												<?php echo esc_html( (string) $row->created_at ); ?>
											</div>
										</td>
										<td style="vertical-align:top;min-width:0;">
											<div class="zq-envelope-cell" data-envelope="<?php echo esc_attr( (string) $row->sealed_envelope ); ?>">
												<span class="zq-locked-pill">🔒 <?php esc_html_e( 'Protected — Unlock safe above to read', 'zubquant' ); ?></span>
											</div>
											<details style="margin-top:6px;font-size:11.5px;color:#646970;">
												<summary style="cursor:pointer;"><?php esc_html_e( 'Inspect Raw Post-Quantum Ciphertext', 'zubquant' ); ?></summary>
												<code style="word-break:break-all;display:block;margin-top:4px;padding:6px;background:#f6f7f7;"><?php echo esc_html( (string) $row->sealed_envelope ); ?></code>
											</details>
										</td>
										<td style="text-align:center;vertical-align:top;padding:10px 4px;">
											<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;" onsubmit="return window.confirm('Delete entry #<?php echo esc_attr( (string) $row->id ); ?> permanently?');">
												<input type="hidden" name="action" value="zubquant_delete_entry" />
												<input type="hidden" name="entry_id" value="<?php echo esc_attr( (string) $row->id ); ?>" />
												<input type="hidden" name="zq_source" value="<?php echo esc_attr( $source_filter ); ?>" />
												<input type="hidden" name="zq_paged" value="<?php echo esc_attr( (string) $current_page ); ?>" />
												<?php wp_nonce_field( 'zubquant_delete_entry_nonce' ); ?>
												<button type="submit" class="zq-del-btn" title="<?php esc_attr_e( 'Delete this entry', 'zubquant' ); ?>">🗑️</button>
											</form>
										</td>
									</tr>
								<?php endforeach; ?>
							<?php endif; ?>
						</tbody>
					</table>

					<!-- VAULT PAGINATION BAR (SCALES TO HUNDREDS / THOUSANDS OF MESSAGES) -->
					<?php if ( $total_filtered_entries > 0 ) : ?>
						<?php
						$showing_from = $offset + 1;
						$showing_to   = min( $offset + $per_page, $total_filtered_entries );
						$base_page_args = array(
							'page'        => 'zubquant-vault',
							'zq_source'   => $source_filter,
							'zq_per_page' => $per_page,
							'zq_s'        => $search_query,
						);
						?>
						<div class="zq-pagination">
							<div>
								<?php
								echo esc_html(
									sprintf(
										/* translators: 1: first item number, 2: last item number, 3: total items */
										__( 'Showing %1$d–%2$d of %3$d protected entries', 'zubquant' ),
										$showing_from,
										$showing_to,
										$total_filtered_entries
									)
								);
								?>
							</div>
							<?php if ( $total_pages > 1 ) : ?>
								<div class="zq-page-links">
									<?php if ( $current_page > 1 ) : ?>
										<a class="zq-page-link" href="<?php echo esc_url( add_query_arg( array_merge( $base_page_args, array( 'zq_paged' => $current_page - 1 ) ), admin_url( 'admin.php' ) ) ); ?>">« <?php esc_html_e( 'Prev', 'zubquant' ); ?></a>
									<?php endif; ?>
									<?php for ( $p = 1; $p <= $total_pages; $p++ ) : ?>
										<?php if ( 1 === $p || $total_pages === $p || abs( $p - $current_page ) <= 2 ) : ?>
											<a class="zq-page-link <?php echo $p === $current_page ? 'zq-page-link--current' : ''; ?>" href="<?php echo esc_url( add_query_arg( array_merge( $base_page_args, array( 'zq_paged' => $p ) ), admin_url( 'admin.php' ) ) ); ?>">
												<?php echo esc_html( (string) $p ); ?>
											</a>
										<?php endif; ?>
									<?php endfor; ?>
									<?php if ( $current_page < $total_pages ) : ?>
										<a class="zq-page-link" href="<?php echo esc_url( add_query_arg( array_merge( $base_page_args, array( 'zq_paged' => $current_page + 1 ) ), admin_url( 'admin.php' ) ) ); ?>"><?php esc_html_e( 'Next', 'zubquant' ); ?> »</a>
									<?php endif; ?>
								</div>
							<?php endif; ?>
						</div>
					<?php endif; ?>
				</div>

				<?php do_action( 'zubquant_admin_after_vault_cards', $this ); ?>

			<?php elseif ( 'passwords' === $active_tab ) : ?>
				<!-- TAB 1 (DEFAULT): WORDPRESS PASSWORD & LOGIN QUANTUM SHIELD -->
				<div class="zq-box" style="border-left:4px solid #8b5cf6;">
					<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:12px;">
						<h2 style="margin:0;">🔑 <?php esc_html_e( 'WordPress Password & Login Quantum Shield (NIST SHA3-512 + Argon2id + ML-DSA-65)', 'zubquant' ); ?></h2>
						<span class="zq-summary-badge">
							<?php
							echo ! empty( $pass_stats['current_user_hardened'] )
								? '🟢 ' . esc_html__( 'Your Admin Account Hardened', 'zubquant' )
								: '⚡ ' . esc_html__( '1-Click Upgrade Available', 'zubquant' );
							?>
						</span>
					</div>

					<!-- ACTIVE SITE-WIDE AUTO-PROTECTION STATUS STRIP -->
					<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:14px;padding:10px 14px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;font-size:12.5px;color:#166534;">
						<strong>🛡️ <?php esc_html_e( 'Active Site-Wide Protections:', 'zubquant' ); ?></strong>
						<span style="background:#fff;border:1px solid #86efac;padding:2px 8px;border-radius:999px;">✓ <?php esc_html_e( 'SHA3-512 + Argon2id Password Shield', 'zubquant' ); ?></span>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=zubquant-vault' ) ); ?>" style="background:#fff;border:1px solid #86efac;padding:2px 8px;border-radius:999px;color:#166534;text-decoration:none;font-weight:600;">
							✓ <?php echo esc_html( sprintf( __( 'Vault & Messages (%d) →', 'zubquant' ), $total_all_entries ) ); ?>
						</a>
						<span style="background:#fff;border:1px solid #86efac;padding:2px 8px;border-radius:999px;">✓ <?php esc_html_e( 'Auto-Form Shield (CF7, WPForms, Elementor, Ninja, Fluent)', 'zubquant' ); ?></span>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=zubquant-audit' ) ); ?>" style="background:#fff;border:1px solid #86efac;padding:2px 8px;border-radius:999px;color:#166534;text-decoration:none;font-weight:600;">✓ <?php esc_html_e( 'ML-DSA-65 Intrusion & Audit Log →', 'zubquant' ); ?></a>
					</div>

					<p style="margin:0 0 16px;color:#475569;font-size:13.5px;line-height:1.6;">
						<?php esc_html_e( 'Standard WordPress passwords use legacy MD5 ($P$) or basic 4KB bcrypt, which are vulnerable to GPU farms and Grover\'s Quantum Search Algorithm. ZubQuant automatically upgrades user accounts on login to NIST FIPS 202 SHA3-512 pre-hashing + Memory-Hard Argon2id (64 MB) and signs every password hash with NIST FIPS 204 ML-DSA-65 to block SQL-injection hash tampering—while keeping wp_users 100% compatible if you ever deactivate the plugin.', 'zubquant' ); ?>
					</p>

					<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));gap:12px;margin-bottom:18px;">
						<div style="background:#f0fdf4;border:1px solid #86efac;border-radius:10px;padding:14px 16px;">
							<div style="font-size:24px;font-weight:700;color:#166534;"><?php echo esc_html( (string) $pass_stats['quantum_hardened'] ); ?> / <?php echo esc_html( (string) $pass_stats['total'] ); ?></div>
							<div style="font-size:13px;font-weight:600;color:#15803d;"><?php esc_html_e( 'Quantum-Hardened Accounts', 'zubquant' ); ?></div>
							<div style="font-size:11.5px;color:#166534;opacity:0.85;"><?php echo esc_html( (string) $pass_stats['current_user_algo'] ); ?> + ML-DSA-65</div>
						</div>
						<div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:10px;padding:14px 16px;">
							<div style="font-size:24px;font-weight:700;color:#1e40af;"><?php echo esc_html( (string) $pass_stats['modern_bcrypt'] ); ?></div>
							<div style="font-size:13px;font-weight:600;color:#1d4ed8;"><?php esc_html_e( 'Standard WP Bcrypt', 'zubquant' ); ?></div>
							<div style="font-size:11.5px;color:#1e40af;opacity:0.85;"><?php esc_html_e( 'Auto-upgrades on next login', 'zubquant' ); ?></div>
						</div>
						<div style="background:<?php echo $pass_stats['legacy_md5'] > 0 ? '#fef2f2' : '#f8fafc'; ?>;border:1px solid <?php echo $pass_stats['legacy_md5'] > 0 ? '#fecaca' : '#e2e8f0'; ?>;border-radius:10px;padding:14px 16px;">
							<div style="font-size:24px;font-weight:700;color:<?php echo $pass_stats['legacy_md5'] > 0 ? '#991b1b' : '#475569'; ?>;"><?php echo esc_html( (string) $pass_stats['legacy_md5'] ); ?></div>
							<div style="font-size:13px;font-weight:600;color:<?php echo $pass_stats['legacy_md5'] > 0 ? '#b91c1c' : '#475569'; ?>;"><?php esc_html_e( 'Legacy Weak MD5 ($P$) Hashes', 'zubquant' ); ?></div>
							<div style="font-size:11.5px;color:#64748b;"><?php esc_html_e( 'Replaced automatically on login', 'zubquant' ); ?></div>
						</div>
					</div>

					<?php if ( isset( $_GET['pass_upgraded'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
						<div style="margin-bottom:14px;padding:12px 16px;background:#dcfce7;border:1px solid #86efac;border-radius:8px;color:#166534;font-weight:600;font-size:13.5px;">
							✅ <?php esc_html_e( 'Your administrator account is now protected with NIST FIPS 202 SHA3-512 + Memory-Hard Argon2id + NIST FIPS 204 ML-DSA-65 signature!', 'zubquant' ); ?>
						</div>
					<?php elseif ( isset( $_GET['pass_upgrade_error'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
						<div style="margin-bottom:14px;padding:12px 16px;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;color:#991b1b;font-weight:600;font-size:13.5px;">
							❌ <?php esc_html_e( 'Could not verify your current WordPress account password. Please try again.', 'zubquant' ); ?>
						</div>
					<?php endif; ?>

					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="background:#f8fafc;border:1px solid #cbd5e1;border-radius:10px;padding:16px 20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
						<input type="hidden" name="action" value="zubquant_upgrade_my_password" />
						<?php wp_nonce_field( 'zubquant_upgrade_my_password_nonce' ); ?>
						<div>
							<strong style="color:#0f172a;font-size:14px;">
								<?php
								echo ! empty( $pass_stats['current_user_hardened'] )
									? '🟢 ' . esc_html__( 'Your Admin Account is Quantum-Hardened (Re-verify or Refresh Signature):', 'zubquant' )
									: '⚡ ' . esc_html__( 'Upgrade Your Admin Account Right Now (Without Logging Out):', 'zubquant' );
								?>
							</strong>
							<span style="display:block;font-size:12.5px;color:#64748b;margin-top:2px;">
								<?php esc_html_e( 'Enter your current WordPress login password to compute your SHA3-512 + Argon2id hash and ML-DSA-65 signature.', 'zubquant' ); ?>
							</span>
						</div>
						<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
							<input type="password" name="zubquant_current_wp_pass" required placeholder="<?php esc_attr_e( 'Your WP login password...', 'zubquant' ); ?>" style="min-width:220px;padding:7px 10px;" />
							<button type="submit" class="button button-primary">
								🛡️ <?php esc_html_e( 'Upgrade My Account to SHA3-512 + Argon2id', 'zubquant' ); ?>
							</button>
						</div>
					</form>

					<!-- ANIMATED PASSWORD & LOGIN QUANTUM SHIELD FLOWCHART -->
					<div class="zq-flow-wrap" style="margin-top:20px;">
						<div class="zq-flow-title"><?php esc_html_e( 'How ZubQuant Password & Login Shield Protects User Accounts in Real Time', 'zubquant' ); ?></div>
						<svg viewBox="0 0 920 235" width="100%" height="auto" role="img" aria-label="<?php esc_attr_e( 'ZubQuant Password and Login Quantum Shield Flowchart', 'zubquant' ); ?>" style="min-width:680px;display:block;margin:0 auto;">
							<defs>
								<linearGradient id="zqPassShieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
									<stop offset="0%" stop-color="#3b0764" />
									<stop offset="100%" stop-color="#6d28d9" />
								</linearGradient>
								<linearGradient id="zqPassSignGrad" x1="0%" y1="0%" x2="100%" y2="100%">
									<stop offset="0%" stop-color="#065f46" />
									<stop offset="100%" stop-color="#047857" />
								</linearGradient>
								<marker id="zqPassArrowPurple" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
									<path d="M 0 1 L 10 5 L 0 9 z" fill="#a78bfa" />
								</marker>
								<marker id="zqPassArrowGreen" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
									<path d="M 0 1 L 10 5 L 0 9 z" fill="#34d399" />
								</marker>
								<marker id="zqPassArrowRed" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
									<path d="M 0 1 L 10 5 L 0 9 z" fill="#f87171" />
								</marker>
							</defs>

							<!-- Node 1: User Login / 1-Click Upgrade -->
							<rect x="14" y="26" width="176" height="104" rx="10" fill="#1e293b" stroke="#475569" stroke-width="1.5" />
							<text x="102" y="52" text-anchor="middle" fill="#f8fafc" font-size="12.5" font-weight="700">1. User Logs In 👤</text>
							<text x="102" y="72" text-anchor="middle" fill="#cbd5e1" font-size="11">Enters WP Password</text>
							<text x="102" y="91" text-anchor="middle" fill="#fca5a5" font-size="10.5">Legacy $P$ MD5 Retired</text>
							<text x="102" y="111" text-anchor="middle" fill="#38bdf8" font-size="10.5" font-weight="600">✓ Zero User Friction</text>

							<!-- Animated Arrow 1 -> 2 -->
							<line x1="190" y1="78" x2="238" y2="78" stroke="#a78bfa" stroke-width="2.5" class="zq-anim-line" marker-end="url(#zqPassArrowPurple)" />

							<!-- Node 2: SHA3-512 + Argon2id (64 MB) -->
							<rect x="245" y="22" width="215" height="112" rx="12" fill="url(#zqPassShieldGrad)" stroke="#a78bfa" stroke-width="2" class="zq-anim-shield" />
							<text x="352" y="48" text-anchor="middle" fill="#ddd6fe" font-size="12.5" font-weight="700">2. Quantum Hash Shield ⚡</text>
							<text x="352" y="69" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="600">NIST FIPS 202 SHA3-512</text>
							<text x="352" y="88" text-anchor="middle" fill="#e9d5ff" font-size="11">+ 64 MB Argon2id RAM Lock</text>
							<text x="352" y="110" text-anchor="middle" fill="#fde68a" font-size="10" font-weight="600">★ Blocks GPUs &amp; Grover&apos;s Algorithm</text>

							<!-- Animated Arrow 2 -> 3 -->
							<line x1="460" y1="78" x2="508" y2="78" stroke="#34d399" stroke-width="2.5" class="zq-anim-line" marker-end="url(#zqPassArrowGreen)" />

							<!-- Node 3: ML-DSA-65 Signed Hash Verification -->
							<rect x="515" y="26" width="188" height="104" rx="10" fill="url(#zqPassSignGrad)" stroke="#34d399" stroke-width="1.5" />
							<text x="609" y="51" text-anchor="middle" fill="#6ee7b7" font-size="12.5" font-weight="700">3. ML-DSA-65 Seal 🔏</text>
							<text x="609" y="71" text-anchor="middle" fill="#ecfdf5" font-size="11">NIST FIPS 204 Signature</text>
							<text x="609" y="90" text-anchor="middle" fill="#a7f3d0" font-size="10.5">Binds user_id + Hash</text>
							<text x="609" y="110" text-anchor="middle" fill="#fde68a" font-size="10" font-weight="600">✓ Verifies DB Integrity</text>

							<!-- Blocked SQLi / Hash Tampering Branch Below Node 3 -->
							<line x1="609" y1="130" x2="609" y2="158" stroke="#f87171" stroke-width="2" stroke-dasharray="4 4" marker-end="url(#zqPassArrowRed)" />
							<rect x="389" y="164" width="440" height="56" rx="8" fill="#450a0a" stroke="#f87171" stroke-width="1.5" class="zq-anim-block" />
							<text x="609" y="187" text-anchor="middle" fill="#fca5a5" font-size="12" font-weight="700">🚫 SQL-Injection &amp; Hash Swap Attacks BLOCKED</text>
							<text x="609" y="206" text-anchor="middle" fill="#fecaca" font-size="10.5">Even if wp_users is edited in MySQL, ML-DSA-65 rejects the login!</text>

							<!-- Animated Arrow 3 -> 4 -->
							<line x1="703" y1="78" x2="746" y2="78" stroke="#34d399" stroke-width="2.5" class="zq-anim-line" marker-end="url(#zqPassArrowGreen)" />

							<!-- Node 4: Verified Login + Dual-Layer WP Compatibility -->
							<rect x="753" y="26" width="153" height="104" rx="10" fill="#1e293b" stroke="#34d399" stroke-width="2" />
							<text x="829" y="51" text-anchor="middle" fill="#6ee7b7" font-size="12.5" font-weight="700">4. Safe Login ✅</text>
							<text x="829" y="71" text-anchor="middle" fill="#f8fafc" font-size="11">Session Verified</text>
							<text x="829" y="90" text-anchor="middle" fill="#cbd5e1" font-size="10.5">wp_users 100% Intact</text>
							<text x="829" y="110" text-anchor="middle" fill="#fde68a" font-size="10" font-weight="600">★ Zero Lockout Risk</text>
						</svg>
					</div>

					<!-- 3-PILLAR NON-TECHNICAL SUMMARY BELOW FLOWCHART -->
					<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:12px;margin-top:14px;">
						<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 14px;font-size:12.5px;color:#334155;line-height:1.5;">
							<strong style="display:block;color:#0f172a;margin-bottom:3px;">1️⃣ <?php esc_html_e( 'Automatic Silent Upgrade on Login', 'zubquant' ); ?></strong>
							<?php esc_html_e( 'You never need to force users to reset their passwords. As each user logs in normally, ZubQuant replaces their weak $P$ MD5 hash and seals their account automatically.', 'zubquant' ); ?>
						</div>
						<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 14px;font-size:12.5px;color:#334155;line-height:1.5;">
							<strong style="display:block;color:#0f172a;margin-bottom:3px;">2️⃣ <?php esc_html_e( 'Stops SQL-Injection Backdoors', 'zubquant' ); ?></strong>
							<?php esc_html_e( 'Even if a hacker exploits another plugin to overwrite an admin password hash in wp_users, they cannot forge the NIST ML-DSA-65 signature—blocking the login attempt and logging an alert.', 'zubquant' ); ?>
						</div>
						<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 14px;font-size:12.5px;color:#334155;line-height:1.5;">
							<strong style="display:block;color:#0f172a;margin-bottom:3px;">3️⃣ <?php esc_html_e( '100% Safe Deactivation Guarantee', 'zubquant' ); ?></strong>
							<?php esc_html_e( 'ZubQuant stores its quantum hash and ML-DSA-65 signature in usermeta while keeping wp_users.user_pass standard WordPress bcrypt—so deactivating the plugin never locks anyone out.', 'zubquant' ); ?>
						</div>
					</div>
				</div>

			<?php elseif ( 'audit' === $active_tab ) : ?>
				<!-- TAB 3: TAMPER-PROOF SECURITY & INTRUSION AUDIT LOG -->
				<div class="zq-box" style="border-left:4px solid #10b981;">
					<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:14px;">
						<div>
							<h2 style="margin:0 0 4px;">🛡️ <?php esc_html_e( 'Tamper-Proof Security & Intrusion Audit Log (NIST FIPS 204 ML-DSA-65 Signed)', 'zubquant' ); ?></h2>
							<p style="margin:0;color:#475569;font-size:13.5px;">
								<?php esc_html_e( 'Automatically signs and hash-chains Admin Logins, Failed Login Attempts, New User Registrations, Role Changes, and Plugin Activations/Deactivations so attackers cannot erase their tracks.', 'zubquant' ); ?>
							</p>
						</div>
						<button type="button" class="button button-primary" id="zq-verify-audit-btn">
							✅ <?php esc_html_e( 'Verify All ML-DSA-65 Signatures in Browser', 'zubquant' ); ?>
						</button>
					</div>

					<table class="widefat striped" style="border-radius:8px;overflow:hidden;">
						<thead>
							<tr>
								<th style="width:46px;"><?php esc_html_e( 'ID', 'zubquant' ); ?></th>
								<th style="width:160px;"><?php esc_html_e( 'Event', 'zubquant' ); ?></th>
								<th style="width:140px;"><?php esc_html_e( 'SHA3-256 Chain', 'zubquant' ); ?></th>
								<th><?php esc_html_e( 'ML-DSA-65 Signature / Verified Payload', 'zubquant' ); ?></th>
								<th style="width:140px;"><?php esc_html_e( 'Timestamp', 'zubquant' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php if ( empty( $audits ) ) : ?>
								<tr><td colspan="5"><?php esc_html_e( 'No audit events recorded yet.', 'zubquant' ); ?></td></tr>
							<?php else : ?>
								<?php foreach ( $audits as $audit ) : ?>
									<tr>
										<td><strong>#<?php echo esc_html( (string) $audit->id ); ?></strong></td>
										<td><code><?php echo esc_html( (string) $audit->event_type ); ?></code></td>
										<td><code><?php echo esc_html( substr( (string) $audit->prev_hash, 0, 14 ) . '...' ); ?></code></td>
										<td>
											<code class="zq-audit-cell" data-token="<?php echo esc_attr( (string) $audit->signed_token ); ?>" style="word-break:break-all;">
												<?php echo esc_html( substr( (string) $audit->signed_token, 0, 56 ) . '...' ); ?>
											</code>
										</td>
										<td><?php echo esc_html( (string) $audit->created_at ); ?></td>
									</tr>
								<?php endforeach; ?>
							<?php endif; ?>
						</tbody>
					</table>

					<?php if ( $total_audits > 0 ) : ?>
						<?php
						$audit_from = $audit_offset + 1;
						$audit_to   = min( $audit_offset + $audit_per_page, $total_audits );
						?>
						<div class="zq-pagination">
							<div>
								<?php
								echo esc_html(
									sprintf(
										/* translators: 1: first audit item, 2: last audit item, 3: total audit items */
										__( 'Showing %1$d–%2$d of %3$d signed audit events', 'zubquant' ),
										$audit_from,
										$audit_to,
										$total_audits
									)
								);
								?>
							</div>
							<?php if ( $total_audit_pages > 1 ) : ?>
								<div class="zq-page-links">
									<?php if ( $audit_page > 1 ) : ?>
										<a class="zq-page-link" href="<?php echo esc_url( add_query_arg( array( 'page' => 'zubquant-audit', 'zq_audit_paged' => $audit_page - 1 ), admin_url( 'admin.php' ) ) ); ?>">« <?php esc_html_e( 'Prev', 'zubquant' ); ?></a>
									<?php endif; ?>
									<?php for ( $ap = 1; $ap <= $total_audit_pages; $ap++ ) : ?>
										<?php if ( 1 === $ap || $total_audit_pages === $ap || abs( $ap - $audit_page ) <= 2 ) : ?>
											<a class="zq-page-link <?php echo $ap === $audit_page ? 'zq-page-link--current' : ''; ?>" href="<?php echo esc_url( add_query_arg( array( 'page' => 'zubquant-audit', 'zq_audit_paged' => $ap ), admin_url( 'admin.php' ) ) ); ?>">
												<?php echo esc_html( (string) $ap ); ?>
											</a>
										<?php endif; ?>
									<?php endfor; ?>
									<?php if ( $audit_page < $total_audit_pages ) : ?>
										<a class="zq-page-link" href="<?php echo esc_url( add_query_arg( array( 'page' => 'zubquant-audit', 'zq_audit_paged' => $audit_page + 1 ), admin_url( 'admin.php' ) ) ); ?>"><?php esc_html_e( 'Next', 'zubquant' ); ?> »</a>
									<?php endif; ?>
								</div>
							<?php endif; ?>
						</div>
					<?php endif; ?>
				</div>

			<?php elseif ( 'settings' === $active_tab ) : ?>
				<!-- TAB 4: GUIDE & CRYPTOGRAPHIC KEY SETTINGS -->
				<div class="zq-box">
					<h2 style="margin:0 0 12px;">⚙️ <?php esc_html_e( 'Advanced & Cryptographic Key Settings (For Developers & Security Auditors)', 'zubquant' ); ?></h2>
					<p style="color:#50575e;">
						<strong><?php esc_html_e( 'Active Cryptographic Suite:', 'zubquant' ); ?></strong>
						<code>IETF X-Wing Hybrid KEM (NIST FIPS 203 ML-KEM-768 + RFC 7748 X25519)</code> + <code>HKDF-SHA256</code> + <code>AES-256-GCM</code> |
						<strong><?php esc_html_e( 'Audit Signatures:', 'zubquant' ); ?></strong>
						<code>NIST FIPS 204 ML-DSA-65 + SHA3-256 Chain</code>
					</p>

					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<input type="hidden" name="action" value="zubquant_save_keys" />
						<?php wp_nonce_field( 'zubquant_save_keys_nonce' ); ?>
						<table class="form-table">
							<tr>
								<th scope="row"><?php esc_html_e( 'Public Encapsulation Key (zpq1_pub_)', 'zubquant' ); ?></th>
								<td>
									<input type="text" name="zubquant_public_key" id="zq-public-key" value="<?php echo esc_attr( $public_key ); ?>" class="large-text code" />
									<p class="description"><?php esc_html_e( 'Safe to store on the server. Used by PHP to encapsulate incoming form submissions into X-Wing (ML-KEM-768 + X25519) capsules.', 'zubquant' ); ?></p>
								</td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'PBKDF2-AES256GCM Locked Private Key Vault', 'zubquant' ); ?></th>
								<td>
									<input type="text" name="zubquant_locked_private_key" id="zq-locked-private-key" value="<?php echo esc_attr( $locked_private_key ); ?>" class="large-text code" />
									<p class="description"><?php esc_html_e( 'Encrypted with your Master Safe Password (PBKDF2-HMAC-SHA256, 210,000 iterations + AES-256-GCM). Leave blank for Strict Air-Gapped Mode.', 'zubquant' ); ?></p>
								</td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'ML-DSA-65 Audit Verification Key (zpq1_vfy_)', 'zubquant' ); ?></th>
								<td>
									<input type="text" id="zq-audit-verify-key" value="<?php echo esc_attr( $verify_key ); ?>" class="large-text code" readonly />
									<p class="description"><?php esc_html_e( 'NIST FIPS 204 Post-Quantum public verification key used to verify tamper-proof admin audit log signatures.', 'zubquant' ); ?></p>
								</td>
							</tr>
						</table>
						<p>
							<?php submit_button( __( 'Update Advanced Key Settings', 'zubquant' ), 'secondary', 'submit', false ); ?>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=zubquant&setup_wizard=1' ) ); ?>" class="button" style="margin-left:8px;">
								<?php esc_html_e( 'Re-run Guided Setup Wizard', 'zubquant' ); ?>
							</a>
						</p>
					</form>
				</div>
			<?php elseif ( 'pro' === $active_tab ) : ?>
				<?php do_action( 'zubquant_admin_render_pro_tab', $this ); ?>
			<?php endif; ?>

			<?php if ( $show_wizard || 'settings' === $active_tab ) : ?>
			<!-- EDUCATIONAL SECTION + ANIMATED FLOWCHART INFOGRAPHIC -->
			<details class="zq-advanced" open style="border-left:4px solid #2563eb;">
				<summary>
					<span>📘 <?php esc_html_e( 'Why Quantum Safety Matters & How ZubQuant Protects Your Website', 'zubquant' ); ?></span>
					<span class="zq-summary-badge"><?php esc_html_e( 'Toggle Guide ▾', 'zubquant' ); ?></span>
				</summary>
				<div style="margin-top:16px;">
					<div class="zq-edu-grid">
						<div class="zq-edu-card">
							<h4>🤔 <?php esc_html_e( '1. What is ZubQuant?', 'zubquant' ); ?></h4>
							<p><?php esc_html_e( 'ZubQuant is a next-generation digital safe for WordPress. Whenever a customer submits a contact form, lead form, or checkout order, ZubQuant locks that sensitive information inside an unbreakable capsule before storing it in your database.', 'zubquant' ); ?></p>
						</div>
						<div class="zq-edu-card zq-danger">
							<h4>⚠️ <?php esc_html_e( '2. The "Harvest Now, Decrypt Later" Threat', 'zubquant' ); ?></h4>
							<p><?php esc_html_e( 'Hackers and bots are stealing encrypted website backups and databases TODAY and saving them until Quantum Computers can crack traditional encryption (RSA/ECC) in seconds. Worse, standard WordPress plugins store their decryption key right inside wp-config.php—so one stolen backup exposes everything immediately!', 'zubquant' ); ?></p>
						</div>
						<div class="zq-edu-card zq-safe">
							<h4>🛡️ <?php esc_html_e( '3. How ZubQuant Makes Your Website Immune (Dual-Shield Protection)', 'zubquant' ); ?></h4>
							<div class="zq-safe-pillars">
								<div class="zq-safe-pillar">
									<strong>🔒 <?php esc_html_e( 'Shield A: Zero-Knowledge Drop-Box Architecture', 'zubquant' ); ?></strong>
									<?php esc_html_e( 'Your WordPress server NEVER holds the decryption key—only the locking key. Even if a hacker steals both your MySQL database and wp-config.php, they cannot unlock a single entry.', 'zubquant' ); ?>
								</div>
								<div class="zq-safe-pillar">
									<strong>⚛️ <?php esc_html_e( 'Shield B: NIST FIPS 203 & 204 Post-Quantum Cryptography', 'zubquant' ); ?></strong>
									<?php esc_html_e( 'Powered by Hybrid X-Wing (ML-KEM-768 + X25519 + AES-256-GCM) and ML-DSA-65 signatures—the exact U.S. NIST standards designed to defeat both classical and future Quantum Supercomputers.', 'zubquant' ); ?>
								</div>
							</div>
						</div>
					</div>

					<!-- ANIMATED SVG FLOWCHART INFOGRAPHIC -->
					<div class="zq-flow-wrap">
						<div class="zq-flow-title">⚡ <?php esc_html_e( 'Live Data Protection Architecture — How Your Website Stays Safe', 'zubquant' ); ?></div>
						<svg viewBox="0 0 920 230" width="100%" height="auto" style="min-width:680px;display:block;margin:0 auto;" role="img" aria-label="ZubQuant Post-Quantum Protection Flowchart">
							<defs>
								<linearGradient id="zqBoxGrad" x1="0%" y1="0%" x2="100%" y2="100%">
									<stop offset="0%" stop-color="#1e293b" />
									<stop offset="100%" stop-color="#0f172a" />
								</linearGradient>
								<linearGradient id="zqSafeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
									<stop offset="0%" stop-color="#065f46" />
									<stop offset="100%" stop-color="#064e3b" />
								</linearGradient>
								<marker id="zqArrowGreen" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
									<path d="M 0 1 L 10 5 L 0 9 z" fill="#34d399" />
								</marker>
								<marker id="zqArrowRed" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
									<path d="M 0 1 L 10 5 L 0 9 z" fill="#f87171" />
								</marker>
							</defs>

							<!-- Node 1: Visitor / Form -->
							<rect x="16" y="32" width="175" height="92" rx="10" fill="url(#zqBoxGrad)" stroke="#38bdf8" stroke-width="2" />
							<text x="103" y="60" text-anchor="middle" fill="#38bdf8" font-size="13" font-weight="700">1. Visitor / Customer</text>
							<text x="103" y="82" text-anchor="middle" fill="#e2e8f0" font-size="11.5">Submits Form or Order</text>
							<text x="103" y="102" text-anchor="middle" fill="#94a3b8" font-size="10.5">(Name, Email, Notes, PII)</text>

							<!-- Animated Arrow 1 -> 2 -->
							<line x1="191" y1="78" x2="245" y2="78" stroke="#34d399" stroke-width="2.5" class="zq-anim-line" marker-end="url(#zqArrowGreen)" />

							<!-- Node 2: Quantum Lock (Public Key) -->
							<rect x="252" y="24" width="195" height="108" rx="12" fill="url(#zqSafeGrad)" stroke="#34d399" stroke-width="2" class="zq-anim-shield" />
							<text x="349" y="52" text-anchor="middle" fill="#6ee7b7" font-size="13" font-weight="700">2. Quantum Drop-Slot Lock</text>
							<text x="349" y="73" text-anchor="middle" fill="#ecfdf5" font-size="11.5">Hybrid X-Wing Encapsulation</text>
							<text x="349" y="92" text-anchor="middle" fill="#a7f3d0" font-size="10.5">ML-KEM-768 + X25519 + AES-256</text>
							<text x="349" y="112" text-anchor="middle" fill="#fde68a" font-size="10" font-weight="600">★ Uses Public Key Only</text>

							<!-- Animated Arrow 2 -> 3 -->
							<line x1="447" y1="78" x2="501" y2="78" stroke="#34d399" stroke-width="2.5" class="zq-anim-line" marker-end="url(#zqArrowGreen)" />

							<!-- Node 3: WordPress Database (Zero-Knowledge Vault) -->
							<rect x="508" y="32" width="185" height="92" rx="10" fill="url(#zqBoxGrad)" stroke="#818cf8" stroke-width="2" />
							<text x="600" y="58" text-anchor="middle" fill="#a5b4fc" font-size="13" font-weight="700">3. WordPress Database</text>
							<text x="600" y="79" text-anchor="middle" fill="#e2e8f0" font-size="11.5">Stores Sealed Capsule</text>
							<text x="600" y="99" text-anchor="middle" fill="#94a3b8" font-size="10.5">(No Decryption Key on Server!)</text>

							<!-- Hacker / Quantum Computer Blocked Branch (Downward from DB) -->
							<line x1="600" y1="124" x2="600" y2="158" stroke="#f87171" stroke-width="2" stroke-dasharray="4 4" marker-end="url(#zqArrowRed)" />
							<rect x="390" y="164" width="420" height="56" rx="8" fill="#450a0a" stroke="#f87171" stroke-width="1.5" class="zq-anim-block" />
							<text x="600" y="186" text-anchor="middle" fill="#fca5a5" font-size="12" font-weight="700">🚫 Hackers &amp; Future Quantum Computers BLOCKED</text>
							<text x="600" y="205" text-anchor="middle" fill="#fecaca" font-size="10.5">Even if MySQL + wp-config.php are stolen, data is unreadable!</text>

							<!-- Animated Arrow 3 -> 4 -->
							<line x1="693" y1="78" x2="742" y2="78" stroke="#34d399" stroke-width="2.5" class="zq-anim-line" marker-end="url(#zqArrowGreen)" />

							<!-- Node 4: Admin Browser Unlock -->
							<rect x="749" y="28" width="155" height="100" rx="10" fill="url(#zqSafeGrad)" stroke="#34d399" stroke-width="2" />
							<text x="826" y="54" text-anchor="middle" fill="#6ee7b7" font-size="13" font-weight="700">4. Your Browser 🔓</text>
							<text x="826" y="75" text-anchor="middle" fill="#ecfdf5" font-size="11.5">Master Password</text>
							<text x="826" y="94" text-anchor="middle" fill="#a7f3d0" font-size="10.5">Unlocks Data Locally</text>
							<text x="826" y="113" text-anchor="middle" fill="#fde68a" font-size="10" font-weight="600">★ 100% Zero-Knowledge</text>
						</svg>
					</div>
				</div>
			</details>
			<?php endif; ?>
				</div><!-- /.zq-layout__main -->

				<aside class="zq-layout__side">
					<div class="zq-rail-card">
						<p class="zq-rail-card__eyebrow"><?php esc_html_e( 'How to use', 'zubquant' ); ?></p>
						<ol class="zq-rail-card__steps">
							<li><?php esc_html_e( 'Set your Master Safe Password in the 60-second setup wizard.', 'zubquant' ); ?></li>
							<li><?php esc_html_e( 'Upgrade your Admin login password in 1 click on 🔑 Password & Login Shield (other accounts upgrade automatically on login).', 'zubquant' ); ?></li>
							<li>
								<?php esc_html_e( 'Existing forms (CF7, WPForms, Elementor, Ninja & Fluent) are protected automatically—or add this shortcode to any page and unlock messages anytime in 📬 Vault & Messages:', 'zubquant' ); ?><br />
								<button type="button" class="zq-shortcode-badge" data-zq-copy="[zubquant_secure_form]" title="<?php esc_attr_e( 'Click to copy shortcode', 'zubquant' ); ?>">
									<span>[zubquant_secure_form]</span>
									<span class="zq-shortcode-badge__hint"><?php esc_html_e( 'Copy', 'zubquant' ); ?></span>
								</button>
							</li>
						</ol>
						<p class="zq-rail-card__actions" style="margin-top:12px;">
							<a class="zq-rail-card__link" href="<?php echo esc_url( home_url( '/zubquant/#docs' ) ); ?>" target="_blank" rel="noopener noreferrer">
								<?php esc_html_e( 'Full Documentation & FAQ ↗', 'zubquant' ); ?>
							</a>
						</p>
					</div>

					<div class="zq-rail-card zq-rail-card--hire">
						<p class="zq-rail-card__eyebrow"><?php esc_html_e( 'Custom development', 'zubquant' ); ?></p>
						<h2 class="zq-rail-card__title"><?php esc_html_e( 'Need something tailored?', 'zubquant' ); ?></h2>
						<p class="zq-rail-card__text">
							<?php esc_html_e( 'I build WordPress plugins, Post-Quantum security integrations, Laravel/Node architectures, and AI workflows for agencies and product teams. If you need custom compliance, E2EE portals, or enterprise integration, get in touch.', 'zubquant' ); ?>
						</p>
						<p class="zq-rail-card__byline">
							<?php esc_html_e( 'Md. Zubaer Ahammed', 'zubquant' ); ?>
						</p>
						<p class="zq-rail-card__actions">
							<a class="button button-primary zq-rail-card__cta" href="<?php echo esc_url( $contact_url ); ?>" target="_blank" rel="noopener noreferrer">
								<?php esc_html_e( 'Hire me for custom work', 'zubquant' ); ?>
							</a>
							<a class="zq-rail-card__link" href="<?php echo esc_url( $site_url ); ?>" target="_blank" rel="noopener noreferrer">
								<?php esc_html_e( 'zubaer.com', 'zubquant' ); ?>
							</a>
						</p>
					</div>

					<div class="zq-rail-card">
						<p class="zq-rail-card__eyebrow"><?php esc_html_e( 'Upgrade & Support', 'zubquant' ); ?></p>
						<h2 class="zq-rail-card__title"><?php esc_html_e( 'Get ZubQuant Pro or Support', 'zubquant' ); ?></h2>
						<p class="zq-rail-card__text">
							<?php esc_html_e( 'Need WooCommerce order sealing, encrypted file drop-boxes, multi-admin access, or automated .zpq1 quantum backups? Get ZubQuant Pro ($49) on Patreon Shop, or support ongoing free development.', 'zubquant' ); ?>
						</p>
						<p class="zq-rail-card__actions">
							<a class="button button-primary zq-rail-card__cta" href="<?php echo esc_url( $pro_url ); ?>" target="_blank" rel="noopener noreferrer">
								<?php esc_html_e( 'Get ZubQuant Pro ($49) ↗', 'zubquant' ); ?>
							</a>
							<a class="zq-rail-card__link" href="<?php echo esc_url( $donate_url ); ?>" target="_blank" rel="noopener noreferrer">
								<?php esc_html_e( 'Support on Patreon', 'zubquant' ); ?>
							</a>
						</p>
					</div>
				</aside>
			</div><!-- /.zq-layout -->
		</div>

		<script>
		document.addEventListener('DOMContentLoaded', function () {
			const SESSION_STORAGE_KEY = 'zubquant_unlocked_privkey';

			function downloadRecoveryKitFile(privKey, pubKey) {
				const kitText = [
					'=============================================================',
					'ZUBQUANT POST-QUANTUM EMERGENCY RECOVERY KIT (KEEP SECRET!)',
					'Website: ' + window.location.origin,
					'Generated: ' + new Date().toISOString(),
					'=============================================================',
					'',
					'IMPORTANT SECURITY INSTRUCTIONS:',
					'1. Store this file in a secure Password Manager (1Password,',
					'   Bitwarden, Apple/Google Passwords) or an offline USB drive.',
					'2. NEVER upload this file to your public website or share it.',
					'3. If you ever forget your Master Safe Password, paste the',
					'   EMERGENCY PRIVATE KEY below into the ZubQuant Unlock box:',
					'',
					'EMERGENCY PRIVATE KEY (SECRET - UNLOCKS ALL MESSAGES):',
					privKey,
					'',
					'PUBLIC ENCAPSULATION KEY (SAFE FOR SERVER):',
					pubKey,
					'============================================================='
				].join('\n');
				const blob = new Blob([kitText], { type: 'text/plain;charset=utf-8' });
				const link = document.createElement('a');
				link.href = URL.createObjectURL(blob);
				link.download = 'zubquant-recovery-kit.txt';
				document.body.appendChild(link);
				link.click();
				document.body.removeChild(link);
			}

			// 1. Guided Onboarding Wizard Handler (Supports Standard, Restore Recovery Key, and Custom Air-Gapped Modes)
			const wizForm = document.getElementById('zq-wizard-form');
			if (wizForm) {
				const modeRadios = wizForm.querySelectorAll('input[name="zq_wiz_mode"]');
				const restoreBox = document.getElementById('zq-wiz-restore-box');
				const customPubBox = document.getElementById('zq-wiz-custom-pub-box');
				const airgapRow = document.getElementById('zq-wiz-airgap-row');
				const pass1Input = document.getElementById('zq-wiz-pass1');
				const pass2Input = document.getElementById('zq-wiz-pass2');

				function syncWizardModeUI() {
					const selected = wizForm.querySelector('input[name="zq_wiz_mode"]:checked');
					const mode = selected ? selected.value : 'generate';
					if (restoreBox) restoreBox.style.display = mode === 'restore' ? 'block' : 'none';
					if (customPubBox) customPubBox.style.display = mode === 'custom_pub' ? 'block' : 'none';
					if (airgapRow) airgapRow.style.display = mode === 'custom_pub' ? 'none' : 'block';
					if (pass1Input && pass2Input) {
						const needPass = mode !== 'custom_pub';
						pass1Input.required = needPass;
						pass2Input.required = needPass;
					}
				}
				modeRadios.forEach(function (r) {
					r.addEventListener('change', syncWizardModeUI);
				});

				wizForm.addEventListener('submit', async function (e) {
					const pubInput = document.getElementById('zq-wiz-public-key');
					if (pubInput.value !== '') return; // Already prepared, proceed with submit
					e.preventDefault();

					const selected = wizForm.querySelector('input[name="zq_wiz_mode"]:checked');
					const mode = selected ? selected.value : 'generate';
					const airgapOnly = document.getElementById('zq-wiz-airgap-only') && document.getElementById('zq-wiz-airgap-only').checked;

					// Mode C: Custom Public Key (CLI / Air-Gapped)
					if (mode === 'custom_pub') {
						const customPub = (document.getElementById('zq-wiz-custom-pub').value || '').trim();
						const customVault = (document.getElementById('zq-wiz-custom-vault').value || '').trim();
						if (!customPub.startsWith('zpq1_pub_')) {
							window.alert('Please enter a valid ZubQuant Public Key starting with zpq1_pub_');
							return;
						}
						pubInput.value = customPub;
						document.getElementById('zq-wiz-locked-key').value = customVault;
						wizForm.submit();
						return;
					}

					const pass1 = pass1Input.value;
					const pass2 = pass2Input.value;
					if (!airgapOnly && pass1 !== pass2) {
						window.alert('Master Passwords do not match. Please check and try again.');
						return;
					}

					const btn = document.getElementById('zq-wiz-submit-btn');
					btn.disabled = true;
					btn.textContent = 'Generating Quantum-Safe Keys in Browser...';

					try {
						let kp;
						if (mode === 'restore') {
							const existingSec = (document.getElementById('zq-wiz-restore-sec').value || '').trim();
							if (!existingSec.startsWith('zpq1_sec_')) {
								throw new Error('Please paste a valid Emergency Private Key starting with zpq1_sec_');
							}
							const seed32 = window.ZubQuant.fromBase64Url(existingSec.slice('zpq1_sec_'.length));
							kp = window.ZubQuant.generateKeyPair(seed32);
						} else {
							kp = window.ZubQuant.generateKeyPair();
						}

						const locked = airgapOnly ? '' : await window.ZubQuant.protectPrivateKey(kp.privateKey, pass1);
						pubInput.value = kp.publicKey;
						document.getElementById('zq-wiz-locked-key').value = locked;

						// Keep unlocked in sessionStorage so their safe is immediately unlocked after redirect!
						sessionStorage.setItem(SESSION_STORAGE_KEY, kp.privateKey);

						// Auto-download Emergency Recovery Kit (.txt) if checked or if Strict Air-Gapped Mode is enabled
						const downloadKit = document.getElementById('zq-wiz-download-kit');
						if ((downloadKit && downloadKit.checked) || airgapOnly) {
							downloadRecoveryKitFile(kp.privateKey, kp.publicKey);
						}

						wizForm.submit();
					} catch (err) {
						btn.disabled = false;
						btn.textContent = '🛡️ Activate Quantum Protection Now (Recommended)';
						window.alert('Setup error: ' + err.message);
					}
				});
			}

			// 2. Helper to format decrypted JSON into compact, collapsible HTML cards
			function renderFriendlyPayload(container, rawText) {
				try {
					const parsed = JSON.parse(rawText);
					if (parsed && typeof parsed === 'object') {
						const entries = Object.entries(parsed);
						const details = document.createElement('details');
						details.className = 'zq-decrypted-card';

						const summary = document.createElement('summary');
						const previewSpan = document.createElement('span');
						previewSpan.className = 'zq-decrypted-preview';

						const snippetParts = entries
							.filter(function ([k]) { return k !== '_file_base64'; })
							.map(function ([k, v]) {
								const valStr = typeof v === 'object' ? JSON.stringify(v) : String(v);
								return k + ': ' + valStr;
							});
						previewSpan.textContent = '🔓 ' + snippetParts.join(' · ');

						const badgeSpan = document.createElement('span');
						badgeSpan.className = 'zq-decrypted-toggle';
						badgeSpan.textContent = 'View Message ▾';

						summary.appendChild(previewSpan);
						summary.appendChild(badgeSpan);

						const body = document.createElement('div');
						body.className = 'zq-decrypted-body';

						for (const [k, v] of entries) {
							if (k === '_file_base64') continue;
							const row = document.createElement('div');
							row.className = 'zq-decrypted-row';
							const strong = document.createElement('strong');
							strong.textContent = k + ':';
							const val = document.createElement('span');
							val.textContent = typeof v === 'object' ? JSON.stringify(v) : String(v);
							row.appendChild(strong);
							row.appendChild(val);
							body.appendChild(row);
						}

						if (parsed._file_base64 && parsed.FileName) {
							const dlWrap = document.createElement('div');
							dlWrap.style.marginTop = '8px';
							const dlBtn = document.createElement('button');
							dlBtn.type = 'button';
							dlBtn.className = 'button button-primary button-small';
							dlBtn.textContent = '⬇️ Download Decrypted File (' + parsed.FileName + ')';
							dlBtn.addEventListener('click', function () {
								const byteChars = atob(parsed._file_base64);
								const byteNumbers = new Array(byteChars.length);
								for (let i = 0; i < byteChars.length; i++) {
									byteNumbers[i] = byteChars.charCodeAt(i);
								}
								const blob = new Blob([new Uint8Array(byteNumbers)], { type: parsed.MimeType || 'application/octet-stream' });
								const a = document.createElement('a');
								a.href = URL.createObjectURL(blob);
								a.download = parsed.FileName;
								document.body.appendChild(a);
								a.click();
								document.body.removeChild(a);
							});
							dlWrap.appendChild(dlBtn);
							body.appendChild(dlWrap);
						}

						details.addEventListener('toggle', function () {
							badgeSpan.textContent = details.open ? 'Hide ▴' : 'View Message ▾';
						});

						details.appendChild(summary);
						details.appendChild(body);
						container.innerHTML = '';
						container.appendChild(details);
						return;
					}
				} catch (_) {}
				container.textContent = '🔓 ' + rawText;
			}

			async function unlockTableWithPrivateKey(privKey) {
				const cells = document.querySelectorAll('.zq-envelope-cell');
				for (const cell of cells) {
					const env = cell.getAttribute('data-envelope');
					const plain = await window.ZubQuant.open(env, privKey);
					renderFriendlyPayload(cell, plain);
				}
				const statusLabel = document.getElementById('zq-safe-status-label');
				if (statusLabel) {
					statusLabel.innerHTML = '<strong style="color:#007017;">🔓 Safe Unlocked</strong> <span style="color:#646970;font-size:13px;margin-left:6px;">Messages decrypted locally in your browser.</span>';
				}
				const lockBtn = document.getElementById('zq-lock-now-btn');
				if (lockBtn) lockBtn.style.display = 'inline-block';
				const exportRecBtn = document.getElementById('zq-export-recovery-btn');
				if (exportRecBtn) {
					exportRecBtn.style.display = 'inline-block';
					exportRecBtn.onclick = function () {
						const pubEl = document.getElementById('zq-public-key-ref') || document.getElementById('zq-public-key');
						downloadRecoveryKitFile(privKey, pubEl ? pubEl.value : '');
					};
				}
				const redownloadBtn = document.getElementById('zq-redownload-kit-btn');
				if (redownloadBtn) {
					redownloadBtn.onclick = function () {
						const pubEl = document.getElementById('zq-public-key-ref') || document.getElementById('zq-public-key');
						downloadRecoveryKitFile(privKey, pubEl ? pubEl.value : '');
					};
				}
				const copyKeyBtn = document.getElementById('zq-copy-emergency-key-btn');
				if (copyKeyBtn) {
					copyKeyBtn.onclick = function () {
						navigator.clipboard.writeText(privKey);
						copyKeyBtn.textContent = '✅ Copied Emergency Key!';
					};
				}
			}

			// 3. Auto-unlock if private key is stored in sessionStorage for this tab
			const savedSessionKey = sessionStorage.getItem(SESSION_STORAGE_KEY);
			if (savedSessionKey && savedSessionKey.startsWith('zpq1_sec_') && document.querySelector('.zq-envelope-cell')) {
				unlockTableWithPrivateKey(savedSessionKey).catch(() => {
					sessionStorage.removeItem(SESSION_STORAGE_KEY);
				});
			}

			// 4. Manual Unlock Button
			const decryptBtn = document.getElementById('zq-decrypt-all-btn');
			if (decryptBtn) {
				decryptBtn.addEventListener('click', async function () {
					if (!window.ZubQuant) return;
					const inputVal = document.getElementById('zq-unlock-passphrase').value.trim();
					const lockedVaultEl = document.getElementById('zq-locked-private-key-ref') || document.getElementById('zq-locked-private-key');
					const lockedVault = lockedVaultEl ? lockedVaultEl.value.trim() : '';
					if (!inputVal) {
						window.alert('Please enter your Master Safe Password (or paste your Emergency Private Key).');
						return;
					}
					let privKey = inputVal;
					try {
						if (!privKey.startsWith('zpq1_sec_')) {
							try {
								privKey = await window.ZubQuant.unlockPrivateKey(lockedVault, inputVal);
							} catch (primaryErr) {
								let unlockedByTeam = false;
								if (Array.isArray(window.zubquantProTeamEnvelopes)) {
									for (const env of window.zubquantProTeamEnvelopes) {
										try {
											privKey = await window.ZubQuant.unlockPrivateKey(env, inputVal);
											unlockedByTeam = true;
											break;
										} catch (teamErr) {
											// Try next envelope
										}
									}
								}
								if (!unlockedByTeam) {
									throw primaryErr;
								}
							}
						}
						await unlockTableWithPrivateKey(privKey);
						const rememberBox = document.getElementById('zq-remember-session');
						if (rememberBox && rememberBox.checked) {
							sessionStorage.setItem(SESSION_STORAGE_KEY, privKey);
						}
						document.getElementById('zq-unlock-passphrase').value = '';
					} catch (err) {
						window.alert('Could not unlock safe. Please check your Master Password or use your Emergency Recovery Kit.');
					}
				});
			}

			// 5. Lock Safe Button
			const lockBtn = document.getElementById('zq-lock-now-btn');
			if (lockBtn) {
				lockBtn.addEventListener('click', function () {
					sessionStorage.removeItem(SESSION_STORAGE_KEY);
					window.location.reload();
				});
			}

			// 6. Verify Audit Log Signatures Button
			const verifyAuditBtn = document.getElementById('zq-verify-audit-btn');
			if (verifyAuditBtn) {
				verifyAuditBtn.addEventListener('click', function () {
					if (!window.ZubQuant) return;
					const verifyKeyEl = document.getElementById('zq-audit-verify-key-ref') || document.getElementById('zq-audit-verify-key');
					const verifyKey = verifyKeyEl ? verifyKeyEl.value.trim() : '';
					const cells = document.querySelectorAll('.zq-audit-cell');
					for (const cell of cells) {
						const token = cell.getAttribute('data-token');
						const res = window.ZubQuant.verify(token, verifyKey);
						if (res.valid) {
							cell.textContent = '✅ VALID ML-DSA-65: ' + res.payload;
							cell.style.color = '#007017';
						} else {
							cell.textContent = '❌ TAMPERED / INVALID SIGNATURE';
							cell.style.color = '#d63638';
						}
					}
				});
			}

			// 7. Click-to-copy shortcode badges
			document.querySelectorAll('[data-zq-copy]').forEach(function (badge) {
				badge.addEventListener('click', function () {
					const code = badge.getAttribute('data-zq-copy');
					const hint = badge.querySelector('.zq-shortcode-badge__hint');
					if (navigator.clipboard && code) {
						navigator.clipboard.writeText(code);
						if (hint) {
							const orig = hint.textContent;
							hint.textContent = '✓ Copied!';
							hint.style.background = '#16a34a';
							setTimeout(function () {
								hint.textContent = orig;
								hint.style.background = '#2563eb';
							}, 1800);
						}
					}
				});
			});

			// 8. Toggle Secret Note / API Key Drawer
			const toggleSecretBtn = document.getElementById('zq-toggle-secret-form-btn');
			const cancelSecretBtn = document.getElementById('zq-cancel-secret-form-btn');
			const secretDrawer = document.getElementById('zq-secret-form-drawer');
			if (toggleSecretBtn && secretDrawer) {
				toggleSecretBtn.addEventListener('click', function () {
					secretDrawer.style.display = secretDrawer.style.display === 'none' ? 'block' : 'none';
				});
			}
			if (cancelSecretBtn && secretDrawer) {
				cancelSecretBtn.addEventListener('click', function () {
					secretDrawer.style.display = 'none';
				});
			}

			// 9. Instant Live Search across Vault Rows (matches ID, Source, Subject, and Decrypted Message Content)
			const vaultSearchInput = document.getElementById('zq-vault-search');
			if (vaultSearchInput) {
				vaultSearchInput.addEventListener('input', function () {
					const query = vaultSearchInput.value.trim().toLowerCase();
					const rows = document.querySelectorAll('.zq-vault-row');
					rows.forEach(function (row) {
						if (!query) {
							row.style.display = '';
							return;
						}
						const text = (row.textContent || '').toLowerCase();
						row.style.display = text.includes(query) ? '' : 'none';
					});
				});
			}

			// 10. Bulk Select & Bulk Delete Checkboxes
			const selectAllBox = document.getElementById('zq-select-all-rows');
			const rowCheckboxes = document.querySelectorAll('.zq-row-checkbox');
			const bulkTriggerBtn = document.getElementById('zq-bulk-delete-trigger-btn');
			const bulkLabel = document.getElementById('zq-bulk-delete-label');
			const bulkForm = document.getElementById('zq-bulk-delete-form');
			const bulkInputsWrap = document.getElementById('zq-bulk-delete-inputs');

			function syncBulkSelectionUI() {
				const checked = Array.from(rowCheckboxes).filter(function (cb) { return cb.checked; });
				if (bulkTriggerBtn && bulkLabel) {
					if (checked.length > 0) {
						bulkTriggerBtn.style.display = 'inline-block';
						bulkLabel.textContent = 'Delete Selected (' + checked.length + ')';
					} else {
						bulkTriggerBtn.style.display = 'none';
					}
				}
			}

			if (selectAllBox) {
				selectAllBox.addEventListener('change', function () {
					rowCheckboxes.forEach(function (cb) {
						if (cb.closest('tr') && cb.closest('tr').style.display !== 'none') {
							cb.checked = selectAllBox.checked;
						}
					});
					syncBulkSelectionUI();
				});
			}

			rowCheckboxes.forEach(function (cb) {
				cb.addEventListener('change', syncBulkSelectionUI);
			});

			if (bulkTriggerBtn && bulkForm && bulkInputsWrap) {
				bulkTriggerBtn.addEventListener('click', function () {
					const checked = Array.from(rowCheckboxes).filter(function (cb) { return cb.checked; });
					if (checked.length === 0) return;
					if (!window.confirm('Delete ' + checked.length + ' selected vault entries permanently?')) {
						return;
					}
					bulkInputsWrap.innerHTML = '';
					checked.forEach(function (cb) {
						const inp = document.createElement('input');
						inp.type = 'hidden';
						inp.name = 'zq_entry_ids[]';
						inp.value = cb.value;
						bulkInputsWrap.appendChild(inp);
					});
					bulkForm.submit();
				});
			}
		});
		</script>
		<?php
	}
}
