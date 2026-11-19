-- No existing or future tenant is operational merely because it exists.
-- Schema owner = restricted bri_migrator. No runtime identity/roster writes.
ALTER TABLE bri.auth_principals ADD COLUMN deletion_requested_at timestamptz;

CREATE TABLE bri.client_activation (
    tenant_id text PRIMARY KEY REFERENCES bri.tenant_admin_policies(tenant_id),
    activated_by uuid NOT NULL REFERENCES bri.auth_principals(principal_id),
    activated_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

-- One provider observation for one exact native identity in one membership.
-- Only a trusted server-side observer may write it. No JWT, secret, factor ID,
-- browser claim or eligibility boolean from the subject is persisted.
CREATE TABLE bri.client_totp_observations (
    tenant_id text NOT NULL,
    principal_id uuid NOT NULL,
    auth_user_id uuid NOT NULL,
    auth_issuer text NOT NULL,
    observed_at timestamptz NOT NULL,
    verified_until timestamptz,
    PRIMARY KEY (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES bri.auth_tenant_memberships,
    FOREIGN KEY (auth_user_id, principal_id) REFERENCES bri.auth_identity_links(auth_user_id, principal_id),
    CHECK (verified_until IS NULL OR
        (verified_until > observed_at AND verified_until <= observed_at + interval '15 minutes'))
);

-- Only rare governance mutations contend here, not reads, audit or sessions.
-- A real write, not a SELECT lock/advisory lock: stale RR/serializable
-- writers must abort rather than count against an old snapshot.
CREATE TABLE bri.client_governance_fence (id boolean PRIMARY KEY CHECK (id));
INSERT INTO bri.client_governance_fence VALUES (true);

DO $policies$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['client_activation','client_totp_observations','client_governance_fence'] LOOP
        EXECUTE format('REVOKE ALL ON bri.%I FROM PUBLIC,bri_app', t);
        EXECUTE format('ALTER TABLE bri.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE bri.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY governance_owner ON bri.%I TO bri_migrator USING (true) WITH CHECK (true)',t);
    END LOOP;
    -- The owner is subject to FORCE RLS. Private definer routines need to see
    -- all candidate rows, not the signed-in caller's own filtered projection.
    FOREACH t IN ARRAY ARRAY['auth_principals','auth_identity_links','auth_tenant_memberships',
        'tenant_admin_policies','platform_superadmins','auth_role_assignments','role_permissions','org_nodes'] LOOP
        EXECUTE format('CREATE POLICY governance_owner_read ON bri.%I FOR SELECT TO bri_migrator USING (true)',t);
    END LOOP;
END $policies$;

CREATE VIEW bri.governance_eligible AS
SELECT m.tenant_id,m.principal_id,i.auth_user_id
FROM bri.auth_tenant_memberships m
JOIN bri.auth_principals p USING (principal_id)
JOIN bri.client_totp_observations e USING (tenant_id,principal_id)
JOIN bri.auth_identity_links i ON (i.auth_user_id,i.principal_id,i.auth_issuer) =
                                 (e.auth_user_id,e.principal_id,e.auth_issuer)
WHERE m.membership_type='admin' AND m.status='active' AND p.status='active'
  AND p.deletion_requested_at IS NULL AND i.status='active' AND i.provider_type='native'
  AND i.auth_subject=i.auth_user_id::text
  -- A waiting governance statement can predate an entire activation. Test
  -- wall-clock evidence validity after acquiring the fence, not statement start.
  AND e.observed_at <= clock_timestamp() AND e.verified_until > clock_timestamp()
  AND NOT EXISTS (SELECT FROM bri.platform_superadmins s WHERE s.principal_id=p.principal_id);
REVOKE ALL ON bri.governance_eligible FROM PUBLIC,bri_app;

-- 0001 grants tenant-local role catalog DML to the app. A provisioning grant
-- must never be created or reassigned through those legacy permissions.
CREATE POLICY governance_permission_insert ON bri.role_permissions AS RESTRICTIVE FOR INSERT TO bri_app
    WITH CHECK (permission <> 'platform:client_admin:manage');
CREATE POLICY governance_permission_update ON bri.role_permissions AS RESTRICTIVE FOR UPDATE TO bri_app
    USING (permission <> 'platform:client_admin:manage') WITH CHECK (permission <> 'platform:client_admin:manage');
CREATE POLICY governance_permission_delete ON bri.role_permissions AS RESTRICTIVE FOR DELETE TO bri_app
    USING (permission <> 'platform:client_admin:manage');

CREATE FUNCTION bri.governance_actor(t text) RETURNS uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT p.principal_id FROM bri.auth_identity_links i JOIN bri.auth_principals p USING(principal_id)
    JOIN bri.auth_tenant_memberships m USING(principal_id)
    WHERE t=nullif(current_setting('bri.tenant_id',true),'') AND m.tenant_id=t
      AND i.auth_user_id::text=current_setting('bri.auth_user_id',true) AND i.status='active'
      AND p.status='active' AND p.deletion_requested_at IS NULL AND m.status='active'
      AND (m.membership_type<>'platform_superadmin' OR EXISTS
           (SELECT FROM bri.platform_superadmins s WHERE s.principal_id=p.principal_id AND s.status='active'))
$$;

CREATE FUNCTION bri.eligible_client_admin(t text, subject uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT bri.governance_actor(t) IS NOT NULL AND EXISTS
        (SELECT FROM bri.governance_eligible WHERE tenant_id=t AND principal_id=subject)
$$;
CREATE FUNCTION bri.client_is_operational(t text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT bri.governance_actor(t) IS NOT NULL AND EXISTS (
        SELECT FROM bri.client_activation a JOIN bri.tenant_admin_policies p USING(tenant_id)
        WHERE a.tenant_id=t AND (SELECT count(*) FROM bri.governance_eligible WHERE tenant_id=t)>=p.min_emergency_admins)
$$;

CREATE FUNCTION bri.governance_serialize() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE bri.client_governance_fence SET id=true WHERE id;
    IF NOT FOUND THEN RAISE EXCEPTION 'governance fence unavailable'; END IF;
    RETURN NULL;
END $$;

-- Changing identities/memberships can move a row across tenants. Check the
-- OLD eligible principal and OLD tenant BEFORE each possible loss. Multirow
-- mutations see earlier rows; concurrent writers have taken the fence first.
CREATE FUNCTION bri.guard_client_admin_loss() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE who uuid; target_tenant text; target_user uuid;
BEGIN
    IF TG_TABLE_NAME='platform_superadmins' THEN
        who := NEW.principal_id;
    ELSE
        who := OLD.principal_id;
        IF TG_TABLE_NAME='auth_identity_links' THEN target_user := OLD.auth_user_id; END IF;
        IF TG_TABLE_NAME IN ('auth_tenant_memberships','client_totp_observations') THEN
            target_tenant := OLD.tenant_id;
        END IF;
    END IF;
    IF EXISTS (
        SELECT FROM bri.governance_eligible old_admin
        JOIN bri.client_activation a USING(tenant_id) JOIN bri.tenant_admin_policies p USING(tenant_id)
        WHERE old_admin.principal_id=who AND (target_tenant IS NULL OR a.tenant_id=target_tenant)
          AND (target_user IS NULL OR old_admin.auth_user_id=target_user)
          AND (SELECT count(*) FROM bri.governance_eligible x WHERE x.tenant_id=a.tenant_id
               AND x.principal_id<>who)<p.min_emergency_admins
    ) THEN RAISE EXCEPTION 'minimum eligible client administrators required' USING ERRCODE='23514'; END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;

DO $locks$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['auth_principals','auth_identity_links','auth_tenant_memberships',
        'platform_superadmins','tenant_admin_policies','client_activation','client_totp_observations',
        'auth_role_assignments','role_permissions','org_nodes'] LOOP
        EXECUTE format('CREATE TRIGGER governance_serialize BEFORE INSERT OR UPDATE OR DELETE ON bri.%I
                        FOR EACH STATEMENT EXECUTE FUNCTION bri.governance_serialize()',t);
    END LOOP;
    FOREACH t IN ARRAY ARRAY['auth_principals','auth_identity_links','auth_tenant_memberships','client_totp_observations'] LOOP
        EXECUTE format('CREATE TRIGGER governance_guard_delete BEFORE DELETE ON bri.%I
                        FOR EACH ROW EXECUTE FUNCTION bri.guard_client_admin_loss()',t);
    END LOOP;
END $locks$;
CREATE TRIGGER governance_principal_loss BEFORE UPDATE ON bri.auth_principals FOR EACH ROW
WHEN ((OLD.principal_id,OLD.status,OLD.deletion_requested_at) IS DISTINCT FROM
      (NEW.principal_id,NEW.status,NEW.deletion_requested_at)) EXECUTE FUNCTION bri.guard_client_admin_loss();
CREATE TRIGGER governance_membership_loss BEFORE UPDATE ON bri.auth_tenant_memberships FOR EACH ROW
WHEN ((OLD.tenant_id,OLD.principal_id,OLD.membership_type,OLD.status) IS DISTINCT FROM
      (NEW.tenant_id,NEW.principal_id,NEW.membership_type,NEW.status)) EXECUTE FUNCTION bri.guard_client_admin_loss();
CREATE TRIGGER governance_link_loss BEFORE UPDATE ON bri.auth_identity_links FOR EACH ROW
WHEN ((OLD.auth_user_id,OLD.principal_id,OLD.status,OLD.provider_type,OLD.auth_issuer,OLD.auth_subject)
      IS DISTINCT FROM (NEW.auth_user_id,NEW.principal_id,NEW.status,NEW.provider_type,NEW.auth_issuer,NEW.auth_subject))
EXECUTE FUNCTION bri.guard_client_admin_loss();
CREATE TRIGGER governance_platform_insert BEFORE INSERT OR UPDATE OF principal_id ON bri.platform_superadmins
FOR EACH ROW EXECUTE FUNCTION bri.guard_client_admin_loss();
CREATE TRIGGER governance_evidence_rebind BEFORE UPDATE ON bri.client_totp_observations FOR EACH ROW
WHEN ((OLD.tenant_id,OLD.principal_id,OLD.auth_user_id,OLD.auth_issuer) IS DISTINCT FROM
      (NEW.tenant_id,NEW.principal_id,NEW.auth_user_id,NEW.auth_issuer)) EXECUTE FUNCTION bri.guard_client_admin_loss();

-- Do not reject truthful provider negatives: NULL/expiry closes normal operation
-- immediately instead of rolling back the observation to retain a false quorum.
-- The attestor is a separate trusted boundary, never bri_app or an end user.
CREATE FUNCTION bri.record_client_totp_observation(t text, who uuid, uid uuid, issuer text,
                                                  observed timestamptz, valid_until timestamptz)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF observed IS NULL OR observed > clock_timestamp() THEN RAISE EXCEPTION 'invalid observation time'; END IF;
    INSERT INTO bri.client_totp_observations AS e VALUES(t,who,uid,issuer,observed,valid_until)
    ON CONFLICT (tenant_id,principal_id) DO UPDATE SET auth_user_id=excluded.auth_user_id,
        auth_issuer=excluded.auth_issuer, observed_at=excluded.observed_at, verified_until=excluded.verified_until
    WHERE excluded.observed_at > e.observed_at OR
          (excluded.observed_at=e.observed_at AND excluded.verified_until IS NULL);
END $$;

-- Activation is a one-way, platform-governed transition. No automatic backfill,
-- no client-callable override. This is also checked on direct provisioning DML.
CREATE FUNCTION bri.guard_client_activation() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'client activation is immutable'; END IF;
    IF NEW.activated_by IS DISTINCT FROM bri.governance_actor(NEW.tenant_id) OR NOT EXISTS (
        SELECT FROM bri.platform_superadmins s JOIN bri.auth_tenant_memberships m USING(principal_id)
        JOIN bri.auth_role_assignments a USING(tenant_id,principal_id)
        JOIN bri.role_permissions r USING(tenant_id,role_id)
        JOIN bri.org_nodes n ON (n.tenant_id,n.node_id)=(a.tenant_id,a.scope_node_id)
        WHERE s.principal_id=NEW.activated_by AND s.status='active' AND m.tenant_id=NEW.tenant_id
          AND m.membership_type='platform_superadmin' AND m.status='active' AND a.status='active'
          AND n.parent_node_id IS NULL AND r.permission='platform:client_admin:manage'
    ) THEN RAISE EXCEPTION 'platform provisioning required' USING ERRCODE='42501'; END IF;
    IF NOT EXISTS (SELECT FROM bri.tenant_admin_policies p WHERE p.tenant_id=NEW.tenant_id
        AND p.min_emergency_admins <= (SELECT count(*) FROM bri.governance_eligible WHERE tenant_id=p.tenant_id))
    THEN RAISE EXCEPTION 'minimum eligible client administrators required' USING ERRCODE='23514'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER governance_activate BEFORE INSERT OR UPDATE OR DELETE ON bri.client_activation
FOR EACH ROW EXECUTE FUNCTION bri.guard_client_activation();
CREATE FUNCTION bri.activate_client(t text) RETURNS void LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO bri.client_activation(tenant_id,activated_by) VALUES(t,bri.governance_actor(t))
$$;
CREATE FUNCTION bri.guard_client_minimum_change() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT FROM bri.client_activation WHERE tenant_id=OLD.tenant_id) AND
       NEW.min_emergency_admins > (SELECT count(*) FROM bri.governance_eligible WHERE tenant_id=OLD.tenant_id)
    THEN RAISE EXCEPTION 'insufficient eligible administrators for policy change' USING ERRCODE='23514'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER governance_minimum_change BEFORE UPDATE OF min_emergency_admins ON bri.tenant_admin_policies
FOR EACH ROW EXECUTE FUNCTION bri.guard_client_minimum_change();

REVOKE ALL ON FUNCTION bri.governance_actor(text), bri.governance_serialize(), bri.guard_client_admin_loss(),
    bri.guard_client_minimum_change(), bri.guard_client_activation(), bri.activate_client(text),
    bri.record_client_totp_observation(text,uuid,uuid,text,timestamptz,timestamptz),
    bri.client_is_operational(text), bri.eligible_client_admin(text,uuid) FROM PUBLIC,bri_app;
GRANT EXECUTE ON FUNCTION bri.client_is_operational(text), bri.eligible_client_admin(text,uuid) TO bri_app;
