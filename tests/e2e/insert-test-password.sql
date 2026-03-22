-- Insert ephemeral password for testuser.
-- Hash is argon2id of "testpassword123".
INSERT INTO runtime.ephemeral_passwords (user_id, password_hash, issued_by, expires_at)
VALUES (
    'a0000000-0000-0000-0000-000000000001'::uuid,
    '$argon2id$v=19$m=65536,t=3,p=4$n1DmwG2wxIk+OL256Zgh4Q$WnmNUA3XyP1pWjaYv+6ab7CKNrTarOyol3F1lPv5ooI',
    'e2e-test-harness',
    now() + interval '1 hour'
);
