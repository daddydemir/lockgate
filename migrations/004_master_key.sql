-- The master key is stored in the same PostgreSQL database as ciphertext at
-- the operator's request. Restrict database access and protect backups.
CREATE TABLE lockgate_master_key (
  id smallint PRIMARY KEY CHECK (id = 1),
  key_version text NOT NULL CHECK (length(key_version) BETWEEN 1 AND 64),
  key_material bytea NOT NULL CHECK (octet_length(key_material) = 32),
  created_at timestamptz NOT NULL DEFAULT now()
);
