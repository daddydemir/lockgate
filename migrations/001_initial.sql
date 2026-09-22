CREATE TABLE admins (
 id bigserial PRIMARY KEY, username text NOT NULL UNIQUE, password_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE sessions (
 token_hash bytea PRIMARY KEY, admin_id bigint NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
 csrf text NOT NULL, expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE applications (
 id bigserial PRIMARY KEY, name text NOT NULL, environment text NOT NULL,
 enabled boolean NOT NULL DEFAULT true, allowed_paths text[] NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 last_access timestamptz, UNIQUE(name, environment)
);
CREATE TABLE application_tokens (
 id bigserial PRIMARY KEY, application_id bigint NOT NULL REFERENCES applications(id),
 token_hash bytea NOT NULL UNIQUE, created_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz
);
CREATE UNIQUE INDEX one_current_token ON application_tokens(application_id) WHERE revoked_at IS NULL;
CREATE TABLE secrets (
 id bigserial PRIMARY KEY, path text NOT NULL UNIQUE,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE secret_versions (
 id bigserial PRIMARY KEY, secret_id bigint NOT NULL REFERENCES secrets(id), version integer NOT NULL CHECK(version>0),
 ciphertext bytea NOT NULL, nonce bytea NOT NULL, encrypted_dek bytea NOT NULL,
 algorithm text NOT NULL CHECK(algorithm='AES-256-GCM'), key_version text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), created_by bigint NOT NULL REFERENCES admins(id),
 UNIQUE(secret_id, version)
);
CREATE FUNCTION immutable_secret_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'secret versions are immutable'; END $$;
CREATE TRIGGER secret_version_immutable BEFORE UPDATE OR DELETE ON secret_versions FOR EACH ROW EXECUTE FUNCTION immutable_secret_version();
CREATE TABLE access_requests (
 id text PRIMARY KEY, application_id bigint NOT NULL REFERENCES applications(id),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied','revoked')),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 resolved_at timestamptz, resolved_by bigint REFERENCES admins(id)
);
CREATE UNIQUE INDEX one_pending_request ON access_requests(application_id) WHERE status='pending';
CREATE TABLE request_instances (
 id text PRIMARY KEY, request_id text NOT NULL REFERENCES access_requests(id),
 instance_key text NOT NULL, paths text[] NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(),
 UNIQUE(request_id, instance_key)
);
CREATE INDEX request_instances_request ON request_instances(request_id);
CREATE TABLE grants (
 id bigserial PRIMARY KEY, application_id bigint NOT NULL REFERENCES applications(id),
 status text NOT NULL CHECK(status IN ('active','revoked','expired')),
 created_at timestamptz NOT NULL DEFAULT now(), approved_by bigint NOT NULL REFERENCES admins(id),
 expires_at timestamptz, revoked_at timestamptz
);
CREATE UNIQUE INDEX one_active_grant ON grants(application_id) WHERE status='active';
CREATE TABLE audit_events (
 id bigserial PRIMARY KEY, event_type text NOT NULL, actor text NOT NULL,
 application_id bigint REFERENCES applications(id), secret_path text,
 client_ip text NOT NULL DEFAULT '', result text NOT NULL DEFAULT 'success',
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_recent ON audit_events(created_at DESC);
