ALTER TABLE admins
  ADD COLUMN totp_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN totp_ciphertext bytea,
  ADD COLUMN totp_nonce bytea,
  ADD COLUMN totp_encrypted_dek bytea,
  ADD COLUMN totp_algorithm text,
  ADD COLUMN totp_key_version text;

ALTER TABLE admins ADD CONSTRAINT admin_totp_complete CHECK (
  (totp_ciphertext IS NULL AND totp_nonce IS NULL AND totp_encrypted_dek IS NULL AND totp_algorithm IS NULL AND totp_key_version IS NULL AND NOT totp_enabled)
  OR
  (totp_ciphertext IS NOT NULL AND totp_nonce IS NOT NULL AND totp_encrypted_dek IS NOT NULL AND totp_algorithm = 'AES-256-GCM' AND totp_key_version IS NOT NULL)
);
