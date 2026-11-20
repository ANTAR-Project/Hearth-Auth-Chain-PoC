CREATE TYPE policy_effect AS ENUM ('ALLOW', 'DENY');
CREATE TYPE policy_scope AS ENUM ('OWN', 'SHARED', 'ANY');

-- rule_name: AAA.BBB.CCC matching the gateway manifest intent field.
-- resource_qualifier: NULL means "any qualifier".
CREATE TABLE policy_rules
(
    id                 UUID PRIMARY KEY       DEFAULT gen_random_uuid(),
    rule_name          TEXT          NOT NULL,
    domain             TEXT          NOT NULL,
    role               TEXT          NOT NULL,
    action             TEXT          NOT NULL,
    resource_type      TEXT          NOT NULL,
    resource_qualifier TEXT,
    scope              policy_scope  NOT NULL DEFAULT 'OWN',
    effect             policy_effect NOT NULL DEFAULT 'ALLOW',
    conditions         JSONB         NOT NULL DEFAULT '{}',
    priority           INT           NOT NULL DEFAULT 0,
    enabled            BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_by         UUID,
    UNIQUE NULLS NOT DISTINCT (domain, role, action, resource_type, resource_qualifier, scope, effect)
);

CREATE TABLE policy_meta
(
    version BIGINT NOT NULL
);
INSERT INTO policy_meta
VALUES (1);

-- ── Seed: OWNER – all actions × all resource types (72 rows) ───────────────
INSERT INTO policy_rules (rule_name, domain, role, action, resource_type, scope, effect)
SELECT lower(d) || '.' || lower(r) || '.' || lower(a),
       d,
       'OWNER',
       a,
       r,
       'ANY',
       'ALLOW'
FROM unnest(ARRAY['NAS', 'ELEMENT']) d,
     unnest(ARRAY['LIST', 'READ', 'CREATE', 'UPDATE', 'DELETE', 'SHARE', 'CONTROL', 'STREAM', 'MANAGE']) a,
     unnest(ARRAY['WORKSPACE', 'SHARED', 'MEDIA', 'ELEMENT', 'AREA', 'USER', 'GUEST', 'POLICY']) r;

-- ── Seed: RESIDENT – own workspace (5 rows, NAS domain) ───────────────────
INSERT INTO policy_rules (rule_name, domain, role, action, resource_type, scope, effect)
SELECT 'nas.workspace.' || lower(a), 'NAS', 'RESIDENT', a, 'WORKSPACE', 'OWN', 'ALLOW'
FROM unnest(ARRAY['LIST', 'READ', 'CREATE', 'UPDATE', 'DELETE']) a;

-- ── Seed: RESIDENT – shared workspace (SHARED scope) ──────────────────────
INSERT INTO policy_rules (rule_name, domain, role, action, resource_type, resource_qualifier, scope, effect)
VALUES ('nas.shared.read', 'NAS', 'RESIDENT', 'READ', 'SHARED', NULL, 'SHARED', 'ALLOW'),
       ('nas.shared.update', 'NAS', 'RESIDENT', 'UPDATE', 'SHARED', NULL, 'SHARED', 'ALLOW');

-- ── Seed: RESIDENT – media and element (ANY scope) ─────────────────────────
INSERT INTO policy_rules (rule_name, domain, role, action, resource_type, scope, effect)
VALUES ('nas.media.stream', 'NAS', 'RESIDENT', 'STREAM', 'MEDIA', 'ANY', 'ALLOW'),
       ('element.device.control', 'ELEMENT', 'RESIDENT', 'CONTROL', 'ELEMENT', 'ANY', 'ALLOW'),
       ('element.camera.stream', 'ELEMENT', 'RESIDENT', 'STREAM', 'ELEMENT', 'ANY', 'ALLOW');

-- ── Seed: GUEST – shared read only ────────────────────────────────────────
INSERT INTO policy_rules (rule_name, domain, role, action, resource_type, scope, effect)
VALUES ('nas.shared.guest.read', 'NAS', 'GUEST', 'READ', 'SHARED', NULL, 'SHARED', 'ALLOW');

-- ── Seed: GUEST – element CAMERA DENY (explicit) ──────────────────────────
INSERT INTO policy_rules (rule_name, domain, role, action, resource_type, resource_qualifier, scope, effect)
VALUES ('element.camera.guest.deny', 'ELEMENT', 'GUEST', 'STREAM', 'ELEMENT', 'CAMERA', 'ANY', 'DENY');

-- Expected total: 72 (OWNER) + 5 (RESIDENT workspace) + 2 (RESIDENT shared)
--               + 3 (RESIDENT media/element) + 1 (GUEST shared) + 1 (GUEST camera deny) = 84