-- Applied by the restricted bri_migrator, inside the runner's transaction.
-- No seed: an offline platform proofing process must bind a stable human ID
-- (not an e-mail, login, or freshly generated ID per account) and tenant scope.
CREATE TABLE bri.approval_admin_people (
    principal_id uuid PRIMARY KEY,
    person_id uuid NOT NULL UNIQUE,
    tenant_id text NOT NULL,
    scope_node_id text NOT NULL,
    revoked boolean NOT NULL DEFAULT false,
    FOREIGN KEY (tenant_id, principal_id) REFERENCES bri.auth_tenant_memberships,
    FOREIGN KEY (tenant_id, scope_node_id) REFERENCES bri.org_nodes
);
CREATE TABLE bri.privileged_approvals (
    approval_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    action text NOT NULL CHECK (action = 'USER_MFA_RESET'),
    policy_version integer NOT NULL DEFAULT 1 CHECK (policy_version=1),
    required_people integer NOT NULL DEFAULT 2 CHECK (required_people=2),
    target uuid NOT NULL,
    target_auth uuid NOT NULL,
    reason text NOT NULL CHECK (reason IN ('LOST_FACTOR','REPLACED_DEVICE','COMPROMISED_FACTOR')),
    requester uuid NOT NULL REFERENCES bri.approval_admin_people,
    reviewer uuid REFERENCES bri.approval_admin_people,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('PENDING','APPROVED','REJECTED','EXPIRED','EXECUTING','COMPLETED','FAILED')),
    -- Pinned once, BEFORE the first external delete. Never rediscover a replacement on retry.
    factor_ids uuid[],
    FOREIGN KEY (tenant_id,target) REFERENCES bri.auth_tenant_memberships,
    FOREIGN KEY (target_auth,target) REFERENCES bri.auth_identity_links(auth_user_id,principal_id),
    CHECK (expires_at=created_at+interval '24 hours'),
    CHECK (requester<>target AND reviewer IS DISTINCT FROM target AND reviewer IS DISTINCT FROM requester),
    CHECK (state IN ('PENDING','EXPIRED') OR reviewer IS NOT NULL),
    CHECK (factor_ids IS NULL OR cardinality(factor_ids) BETWEEN 1 AND 256)
);
CREATE UNIQUE INDEX privileged_approval_one_open ON bri.privileged_approvals(tenant_id,action,target)
    WHERE state IN ('PENDING','APPROVED','EXECUTING','FAILED');
CREATE TABLE bri.approval_votes (
    approval_id uuid NOT NULL REFERENCES bri.privileged_approvals,
    actor uuid NOT NULL REFERENCES bri.approval_admin_people,
    person_id uuid NOT NULL REFERENCES bri.approval_admin_people(person_id),
    decision text NOT NULL CHECK (decision IN ('REQUEST','APPROVE','REJECT')),
    auth_id uuid NOT NULL,
    session_id uuid NOT NULL,
    totp_at timestamptz NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (approval_id, decision), UNIQUE(approval_id,actor), UNIQUE(approval_id,person_id),
    FOREIGN KEY (auth_id,actor) REFERENCES bri.auth_identity_links(auth_user_id,principal_id)
);
-- Separate append-only lifecycle stream: 0006 security_audit_events has a closed event vocabulary.
CREATE TABLE bri.approval_events (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    approval_id uuid NOT NULL REFERENCES bri.privileged_approvals,
    actor uuid NOT NULL REFERENCES bri.auth_principals,
    correlation_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('PENDING','APPROVED','REJECTED','EXPIRED','EXECUTING','COMPLETED','FAILED')),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
DO $rls$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['approval_admin_people','privileged_approvals','approval_votes','approval_events'] LOOP
        EXECUTE format('ALTER TABLE bri.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE bri.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('REVOKE ALL ON bri.%I FROM PUBLIC, bri_app', t);
        EXECUTE format('CREATE POLICY approval_owner_read ON bri.%I FOR SELECT TO bri_migrator USING (true)',t);
        EXECUTE format('CREATE POLICY approval_owner_append ON bri.%I FOR INSERT TO bri_migrator WITH CHECK (true)',t);
    END LOOP;
    -- Definer-only reads/locks, no runtime grants on underlying identity records.
    FOREACH t IN ARRAY ARRAY['auth_principals','auth_identity_links','auth_tenant_memberships',
        'auth_role_assignments','role_permissions','platform_superadmins','auth_sessions'] LOOP
        EXECUTE format('CREATE POLICY approval_identity_read ON bri.%I FOR SELECT TO bri_migrator USING (true)',t);
    END LOOP;
END
$rls$;
CREATE POLICY approval_state_update ON bri.privileged_approvals FOR UPDATE TO bri_migrator USING (true);
CREATE POLICY approval_person_revoke ON bri.approval_admin_people FOR UPDATE TO bri_migrator USING (NOT revoked) WITH CHECK (revoked);

CREATE FUNCTION bri.approval_person_immutable() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF TG_OP='UPDATE' AND NOT OLD.revoked AND NEW.revoked AND
       (OLD.principal_id,OLD.person_id,OLD.tenant_id,OLD.scope_node_id) IS NOT DISTINCT FROM
       (NEW.principal_id,NEW.person_id,NEW.tenant_id,NEW.scope_node_id) THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'stable person attestation cannot be rebound';
END $$;
CREATE TRIGGER stable_approval_person BEFORE UPDATE OR DELETE ON bri.approval_admin_people
FOR EACH ROW EXECUTE FUNCTION bri.approval_person_immutable();
CREATE TRIGGER immutable_person_registry BEFORE TRUNCATE ON bri.approval_admin_people
FOR EACH STATEMENT EXECUTE FUNCTION bri.deny_audit_mutation();
REVOKE ALL ON FUNCTION bri.approval_person_immutable() FROM PUBLIC,bri_app;
CREATE POLICY approval_audit_completion ON bri.security_audit_events AS RESTRICTIVE FOR INSERT TO bri_app
    WITH CHECK (event_type <> 'auth.mfa.factor_removed');
CREATE POLICY approval_quarantine ON bri.auth_principals FOR UPDATE TO bri_migrator USING (true);
-- 0001 granted legacy DML on this catalog. The two new permissions are not app-provisionable.
CREATE POLICY approval_permission_insert ON bri.role_permissions AS RESTRICTIVE FOR INSERT TO bri_app
    WITH CHECK (permission NOT IN ('user:mfa_reset:request','user:mfa_reset:decide'));
CREATE POLICY approval_permission_change ON bri.role_permissions AS RESTRICTIVE FOR UPDATE TO bri_app
    USING (permission NOT IN ('user:mfa_reset:request','user:mfa_reset:decide'))
    WITH CHECK (permission NOT IN ('user:mfa_reset:request','user:mfa_reset:decide'));

-- Private helpers run only inside guarded entry points. All functions have a fixed search path.
-- Share 0009’s write fence with identity, permission, eligibility and activation writers.
-- Session row locks order each decision with logout; no global session-table lock.
-- Caller supplies READ COMMITTED, otherwise reject stale transaction snapshots.
CREATE TRIGGER immutable_approval_history BEFORE UPDATE OR DELETE OR TRUNCATE ON bri.approval_events
FOR EACH STATEMENT EXECUTE FUNCTION bri.deny_audit_mutation();
CREATE TRIGGER immutable_approval_votes BEFORE UPDATE OR DELETE OR TRUNCATE ON bri.approval_votes
FOR EACH STATEMENT EXECUTE FUNCTION bri.deny_audit_mutation();
CREATE FUNCTION bri.approval_lock() RETURNS void LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'approval requires read committed';
    END IF;
    UPDATE bri.client_governance_fence SET id=true WHERE id;
    IF NOT FOUND THEN RAISE EXCEPTION 'governance unavailable'; END IF;
    LOCK TABLE bri.approval_admin_people IN SHARE MODE;
END $$;
CREATE FUNCTION bri.approval_session(p_auth uuid,p_session uuid) RETURNS uuid LANGUAGE sql VOLATILE
SET search_path=pg_catalog,pg_temp AS $$
    SELECT s.principal_id FROM bri.auth_sessions s JOIN bri.auth_identity_links i USING(auth_user_id,principal_id)
    JOIN bri.auth_principals p USING(principal_id)
    WHERE s.auth_user_id=p_auth AND s.session_id=p_session AND i.status='active' AND p.status='active'
      AND i.auth_issuer=current_setting('bri.auth_issuer',true) AND i.auth_subject=i.auth_user_id::text
      AND s.revoked_at IS NULL AND clock_timestamp() >= s.started_at
      AND clock_timestamp() < least(s.expires_at,s.started_at+interval '8 hours')
    FOR SHARE OF s
$$;
CREATE FUNCTION bri.approval_actor(p_tenant text) RETURNS uuid LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$
DECLARE actor uuid; stamp timestamptz := nullif(current_setting('bri.totp_at',true),'')::timestamptz;
BEGIN
    actor := bri.approval_session(nullif(current_setting('bri.auth_user_id',true),'')::uuid,
                                 nullif(current_setting('bri.session_id',true),'')::uuid);
    IF p_tenant IS NULL OR p_tenant IS DISTINCT FROM nullif(current_setting('bri.tenant_id',true),'') OR
       nullif(current_setting('bri.correlation_id',true),'')::uuid IS NULL OR actor IS NULL OR
       current_setting('bri.aal',true) IS DISTINCT FROM 'aal2' OR stamp IS NULL OR
       stamp > clock_timestamp() OR stamp < clock_timestamp()-interval '15 minutes' OR
       bri.client_is_operational(p_tenant) IS NOT TRUE THEN
        RAISE EXCEPTION 'approval denied' USING ERRCODE='42501';
    END IF;
    RETURN actor;
END $$;
CREATE FUNCTION bri.approval_person(t text, who uuid, perm text) RETURNS uuid LANGUAGE sql VOLATILE
SET search_path=pg_catalog,pg_temp AS $$
    SELECT ap.person_id FROM bri.approval_admin_people ap
    JOIN bri.auth_tenant_memberships m USING(tenant_id,principal_id)
    WHERE ap.principal_id=who AND ap.tenant_id=t AND NOT ap.revoked
      AND m.membership_type='admin' AND m.status='active' AND bri.eligible_client_admin(t,who)
      AND NOT EXISTS (SELECT FROM bri.platform_superadmins s WHERE s.principal_id=who AND s.status='active')
      AND EXISTS (SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions rp USING(tenant_id,role_id)
          WHERE a.principal_id=who AND a.tenant_id=t AND a.scope_node_id=ap.scope_node_id
            AND a.status='active' AND rp.permission=perm AND EXISTS (SELECT FROM bri.org_nodes n
                WHERE n.tenant_id=t AND n.node_id=ap.scope_node_id AND n.parent_node_id IS NULL))
$$;
CREATE FUNCTION bri.approval_target(t text, who uuid, quarantined boolean) RETURNS uuid LANGUAGE sql VOLATILE
SET search_path=pg_catalog,pg_temp AS $$
    SELECT i.auth_user_id FROM bri.auth_identity_links i JOIN bri.auth_principals p USING(principal_id)
    JOIN bri.auth_tenant_memberships m USING(principal_id)
    WHERE m.tenant_id=t AND m.membership_type='user' AND m.status='active' AND i.principal_id=who
      AND p.deletion_requested_at IS NULL AND p.status=CASE WHEN quarantined THEN 'suspended' ELSE 'active' END
      AND i.status='active' AND i.provider_type='native' AND i.auth_subject=i.auth_user_id::text
      AND i.auth_issuer=current_setting('bri.auth_issuer',true)
      AND NOT EXISTS (SELECT FROM bri.auth_identity_links x WHERE x.principal_id=who AND x.auth_user_id<>i.auth_user_id AND x.status='active')
      AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships x WHERE x.principal_id=who AND x.tenant_id<>t)
      AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id=who)
$$;
CREATE FUNCTION bri.approval_event(a uuid, who uuid, st text) RETURNS void LANGUAGE sql
SET search_path=pg_catalog,pg_temp AS $$
    INSERT INTO bri.approval_events(approval_id,actor,correlation_id,state)
    VALUES(a,who,current_setting('bri.correlation_id')::uuid,st);
    INSERT INTO bri.security_audit_events(tenant_id,actor_principal_id,subject_principal_id,event_type,outcome,request_id)
        SELECT tenant_id,who,target,CASE st WHEN 'COMPLETED' THEN 'auth.mfa.factor_removed'
                                      ELSE 'auth.mfa.recovery_initiated' END,
               CASE st WHEN 'FAILED' THEN 'failure' WHEN 'REJECTED' THEN 'denied' ELSE 'success' END,
               current_setting('bri.correlation_id')::uuid FROM bri.privileged_approvals
        WHERE approval_id=a AND st IN ('PENDING','COMPLETED','FAILED');
$$;
CREATE FUNCTION bri.approval_vote(a uuid, who uuid, person uuid, choice text) RETURNS void LANGUAGE sql
SET search_path=pg_catalog,pg_temp AS $$
    INSERT INTO bri.approval_votes(approval_id,actor,person_id,decision,auth_id,session_id,totp_at)
    VALUES(a,who,person,choice,current_setting('bri.auth_user_id')::uuid,current_setting('bri.session_id')::uuid,
           current_setting('bri.totp_at')::timestamptz)
$$;
CREATE FUNCTION bri.approval_recheck(a uuid,t text) RETURNS void LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF EXISTS (SELECT FROM bri.approval_votes v WHERE v.approval_id=a AND
      (v.actor IS DISTINCT FROM bri.approval_session(v.auth_id,v.session_id) OR
       v.person_id IS DISTINCT FROM bri.approval_person(t,v.actor,CASE WHEN v.decision='REQUEST'
                               THEN 'user:mfa_reset:request' ELSE 'user:mfa_reset:decide' END))) THEN
        RAISE EXCEPTION 'approval authority changed' USING ERRCODE='42501';
    END IF;
END $$;
CREATE FUNCTION bri.approval_expire(a uuid,who uuid) RETURNS boolean LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    UPDATE bri.privileged_approvals SET state='EXPIRED' WHERE approval_id=a
        AND state IN ('PENDING','APPROVED') AND expires_at<=clock_timestamp();
    IF FOUND THEN PERFORM bri.approval_event(a,who,'EXPIRED'); RETURN true; END IF;
    RETURN false;
END $$;
CREATE FUNCTION bri.approval_request(t text,act text,target_id uuid,why text,request_key uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE who uuid; person uuid; native_id uuid; r bri.privileged_approvals; stamp timestamptz;
BEGIN
    PERFORM bri.approval_lock(); who := bri.approval_actor(t);
    person := bri.approval_person(t,who,'user:mfa_reset:request');
    IF person IS NULL OR act IS DISTINCT FROM 'USER_MFA_RESET' OR why IS NULL OR
       why NOT IN ('LOST_FACTOR','REPLACED_DEVICE','COMPROMISED_FACTOR') OR request_key IS NULL THEN
        RAISE EXCEPTION 'approval denied' USING ERRCODE='42501'; END IF;
    SELECT * INTO r FROM bri.privileged_approvals WHERE approval_id=request_key FOR UPDATE;
    IF FOUND THEN
        IF (r.tenant_id,r.action,r.target,r.requester,r.reason) IS DISTINCT FROM (t,act,target_id,who,why) THEN
            RAISE EXCEPTION 'request key conflict' USING ERRCODE='23505'; END IF;
        IF bri.approval_expire(r.approval_id,who) THEN RETURN 'EXPIRED'; END IF;
        RETURN r.state;
    END IF;
    native_id := bri.approval_target(t,target_id,false);
    IF native_id IS NULL THEN RAISE EXCEPTION 'approval denied' USING ERRCODE='42501'; END IF;
    PERFORM bri.approval_expire(approval_id,who) FROM bri.privileged_approvals
        WHERE tenant_id=t AND action=act AND target=target_id AND state IN ('PENDING','APPROVED');
    stamp := clock_timestamp();
    INSERT INTO bri.privileged_approvals(approval_id,tenant_id,action,target,target_auth,requester,reason,state,created_at,expires_at)
        VALUES(request_key,t,act,target_id,native_id,who,why,'PENDING',stamp,stamp+interval '24 hours');
    PERFORM bri.approval_vote(request_key,who,person,'REQUEST');
    PERFORM bri.approval_event(request_key,who,'PENDING'); RETURN 'PENDING';
END $$;
CREATE FUNCTION bri.approval_decide(t text,act text,a uuid,choice text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE who uuid; person uuid; r bri.privileged_approvals; st text;
BEGIN
    PERFORM bri.approval_lock(); who := bri.approval_actor(t);
    person := bri.approval_person(t,who,'user:mfa_reset:decide');
    SELECT * INTO r FROM bri.privileged_approvals WHERE approval_id=a AND tenant_id=t AND action=act FOR UPDATE;
    IF NOT FOUND OR person IS NULL OR who=r.requester OR choice IS NULL OR choice NOT IN ('APPROVE','REJECT') THEN
        RAISE EXCEPTION 'approval denied' USING ERRCODE='42501'; END IF;
    IF bri.approval_expire(a,who) THEN RETURN 'EXPIRED'; END IF;
    IF EXISTS (SELECT FROM bri.approval_votes WHERE approval_id=a AND actor=who AND decision=choice) THEN RETURN r.state; END IF;
    IF r.state='EXPIRED' THEN RETURN r.state; END IF;
    IF r.state<>'PENDING' THEN RAISE EXCEPTION 'decision conflict' USING ERRCODE='55000'; END IF;
    PERFORM bri.approval_recheck(a,t);
    IF bri.approval_target(t,r.target,false) IS DISTINCT FROM r.target_auth THEN
        RAISE EXCEPTION 'approval target changed' USING ERRCODE='42501'; END IF;
    st := CASE choice WHEN 'APPROVE' THEN 'APPROVED' ELSE 'REJECTED' END;
    PERFORM bri.approval_vote(a,who,person,choice);
    UPDATE bri.privileged_approvals SET reviewer=who,state=st WHERE approval_id=a;
    PERFORM bri.approval_event(a,who,st); RETURN st;
END $$;

-- 0009 serializes these governance changes before the row trigger runs. Keep
-- an in-flight provider subject from becoming an admin or being rebound across
-- a committed dispatch and its external effect. Never block a denial/revocation.
CREATE FUNCTION bri.approval_guard_target_change() RETURNS trigger LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE protected_ids uuid[];
BEGIN
    protected_ids := ARRAY[NEW.principal_id];
    IF TG_OP='UPDATE' THEN protected_ids:=array_append(protected_ids,OLD.principal_id); END IF;
    IF EXISTS (SELECT FROM bri.privileged_approvals r WHERE r.target=ANY(protected_ids)
               AND r.state IN ('EXECUTING','FAILED')) THEN
        RAISE EXCEPTION 'approval recovery in progress' USING ERRCODE='55000'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER approval_freeze_platform BEFORE INSERT OR UPDATE ON bri.platform_superadmins
FOR EACH ROW WHEN (NEW.status='active') EXECUTE FUNCTION bri.approval_guard_target_change();
CREATE TRIGGER approval_freeze_member BEFORE INSERT OR UPDATE ON bri.auth_tenant_memberships
FOR EACH ROW WHEN (NEW.status='active') EXECUTE FUNCTION bri.approval_guard_target_change();
CREATE TRIGGER approval_freeze_identity BEFORE INSERT OR UPDATE ON bri.auth_identity_links
FOR EACH ROW WHEN (NEW.status='active') EXECUTE FUNCTION bri.approval_guard_target_change();
CREATE TRIGGER approval_freeze_principal BEFORE UPDATE OF status ON bri.auth_principals
FOR EACH ROW WHEN (NEW.status='active') EXECUTE FUNCTION bri.approval_guard_target_change();
REVOKE ALL ON FUNCTION bri.approval_guard_target_change() FROM PUBLIC,bri_app;

-- One committed permit per provider factor. A lost acknowledgement permits
-- reconciliation, not a second destructive call. A still-present ambiguous
-- factor stays quarantined for platform review; a replacement is never removed.
CREATE TABLE bri.approval_dispatches (
    approval_id uuid NOT NULL REFERENCES bri.privileged_approvals,
    factor_id uuid NOT NULL,
    dispatched_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    absent_at timestamptz,
    PRIMARY KEY(approval_id,factor_id)
);
ALTER TABLE bri.approval_dispatches ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.approval_dispatches FORCE ROW LEVEL SECURITY;
REVOKE ALL ON bri.approval_dispatches FROM PUBLIC,bri_app;
CREATE POLICY approval_dispatch_read ON bri.approval_dispatches FOR SELECT TO bri_migrator USING (true);
CREATE POLICY approval_dispatch_ack ON bri.approval_dispatches FOR UPDATE TO bri_migrator USING (absent_at IS NULL) WITH CHECK (absent_at IS NOT NULL);
CREATE POLICY approval_dispatch_append ON bri.approval_dispatches FOR INSERT TO bri_migrator WITH CHECK (true);

CREATE FUNCTION bri.approval_status(t text,act text,a uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE who uuid; r bri.privileged_approvals;
BEGIN
    PERFORM bri.approval_lock(); who:=bri.approval_actor(t);
    SELECT * INTO r FROM bri.privileged_approvals WHERE approval_id=a AND tenant_id=t AND action=act FOR UPDATE;
    IF NOT FOUND OR (bri.approval_person(t,who,'user:mfa_reset:decide') IS NULL AND
        (who<>r.requester OR bri.approval_person(t,who,'user:mfa_reset:request') IS NULL)) THEN
        RAISE EXCEPTION 'approval denied' USING ERRCODE='42501'; END IF;
    IF bri.approval_expire(a,who) THEN RETURN 'EXPIRED'; END IF;
    RETURN r.state;
END $$;

-- Worker only. No identity/target/state supplied by the browser; its transaction
-- scope must carry verified, fresh step-up for the recorded second decision maker.
CREATE FUNCTION bri.approval_work(t text,act text,a uuid,op text,ids uuid[])
RETURNS TABLE(stage text, auth_target uuid, pinned uuid[], permit boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE who uuid; r bri.privileged_approvals; granted boolean := false; st text;
BEGIN
    PERFORM bri.approval_lock(); who:=bri.approval_actor(t);
    SELECT * INTO r FROM bri.privileged_approvals WHERE approval_id=a AND tenant_id=t AND action=act FOR UPDATE;
    IF NOT FOUND OR who IS DISTINCT FROM r.reviewer OR bri.approval_person(t,who,'user:mfa_reset:decide') IS NULL
       OR op IS NULL OR op NOT IN ('BEGIN','PIN','DISPATCH','ABSENT','FAILED','VERIFIED','STATUS') THEN
        RAISE EXCEPTION 'approval denied' USING ERRCODE='42501'; END IF;
    IF bri.approval_expire(a,who) OR r.state='EXPIRED' THEN RETURN QUERY SELECT 'EXPIRED'::text,NULL::uuid,NULL::uuid[],false; RETURN; END IF;
    IF r.state='COMPLETED' THEN RETURN QUERY SELECT r.state,NULL::uuid,NULL::uuid[],false; RETURN; END IF;
    IF op='STATUS' THEN RETURN QUERY SELECT r.state,NULL::uuid,NULL::uuid[],false; RETURN; END IF;
    IF r.state NOT IN ('APPROVED','EXECUTING','FAILED') OR (r.state='APPROVED' AND op<>'BEGIN') OR
       NOT EXISTS (SELECT FROM bri.approval_votes WHERE approval_id=a AND actor=r.reviewer AND decision='APPROVE') THEN
        RAISE EXCEPTION 'approval execution conflict' USING ERRCODE='55000'; END IF;
    PERFORM bri.approval_recheck(a,t);
    IF bri.approval_target(t,r.target,r.state<>'APPROVED') IS DISTINCT FROM r.target_auth OR
       (r.state<>'APPROVED' AND NOT EXISTS (SELECT FROM bri.credential_operations co
           WHERE co.operation_id=a AND co.principal_id=r.target AND co.auth_user_id=r.target_auth
             AND co.kind='factor_reenrollment' AND co.confirmed_at IS NULL)) THEN
        RAISE EXCEPTION 'approval target changed' USING ERRCODE='42501'; END IF;
    st:=r.state;
    IF r.expires_at <= clock_timestamp() THEN
        -- Never authorize a new mutation after the window. Do not lift quarantine.
        st:='FAILED';
    ELSIF op='BEGIN' THEN
        IF r.state='APPROVED' THEN
            UPDATE bri.auth_principals SET status='suspended',status_changed_at=clock_timestamp()
                WHERE principal_id=r.target AND status='active';
            IF NOT FOUND THEN RAISE EXCEPTION 'quarantine failed'; END IF;
            IF bri.reserve_factor_reenrollment(r.target_auth,who,a,
                    current_setting('bri.correlation_id')::uuid) IS NOT TRUE THEN
                RAISE EXCEPTION 'credential operation conflict' USING ERRCODE='55000'; END IF;
        END IF;
        st:='EXECUTING';
    ELSIF op='FAILED' THEN st:='FAILED';
    ELSIF r.state<>'EXECUTING' THEN RAISE EXCEPTION 'approval execution conflict' USING ERRCODE='55000';
    ELSIF op='PIN' THEN
        IF ids IS NULL OR cardinality(ids) NOT BETWEEN 1 AND 256 OR array_ndims(ids)<>1 OR
           cardinality(ids)<>(SELECT count(DISTINCT id) FROM unnest(ids) id) THEN
            RAISE EXCEPTION 'invalid factor inventory'; END IF;
        IF r.factor_ids IS NULL THEN
            UPDATE bri.privileged_approvals SET factor_ids=ids WHERE approval_id=a; r.factor_ids:=ids;
        END IF;
    ELSIF op='DISPATCH' THEN
        IF ids IS NULL OR cardinality(ids)<>1 OR (ids[1]=ANY(r.factor_ids)) IS NOT TRUE THEN
            RAISE EXCEPTION 'unapproved factor'; END IF;
        INSERT INTO bri.approval_dispatches(approval_id,factor_id) VALUES(a,ids[1]) ON CONFLICT DO NOTHING;
        granted:=FOUND;
    ELSIF op='ABSENT' THEN
        IF ids IS NULL OR cardinality(ids)<>1 OR (ids[1]=ANY(r.factor_ids)) IS NOT TRUE THEN
            RAISE EXCEPTION 'unapproved evidence'; END IF;
        UPDATE bri.approval_dispatches SET absent_at=clock_timestamp()
            WHERE approval_id=a AND factor_id=ids[1] AND absent_at IS NULL;
    ELSIF op='VERIFIED' THEN
        -- Only the isolated provider worker attests its authoritative post-read;
        -- a transport 2xx, empty uninitialized plan or caller boolean isn't evidence.
        IF ids IS DISTINCT FROM ARRAY[]::uuid[] OR r.factor_ids IS NULL OR EXISTS (
            SELECT FROM unnest(r.factor_ids) id WHERE NOT EXISTS (
                SELECT FROM bri.approval_dispatches d WHERE d.approval_id=a AND d.factor_id=id AND d.absent_at IS NOT NULL)) THEN
            RAISE EXCEPTION 'provider removal unverified'; END IF;
        st:='COMPLETED';
    END IF;
    IF st<>r.state THEN
        UPDATE bri.privileged_approvals SET state=st WHERE approval_id=a;
        PERFORM bri.approval_event(a,who,st);
    END IF;
    RETURN QUERY SELECT st,r.target_auth,r.factor_ids,granted;
END $$;
DO $privileges$
DECLARE f regprocedure;
BEGIN
    FOR f IN SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
       WHERE n.nspname='bri' AND p.proname IN ('approval_lock','approval_session','approval_actor',
          'approval_person','approval_target','approval_event','approval_vote','approval_recheck','approval_expire',
          'approval_request','approval_decide','approval_status','approval_work') LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,bri_app',f);
    END LOOP;
END $privileges$;
GRANT EXECUTE ON FUNCTION bri.approval_request(text,text,uuid,text,uuid),
    bri.approval_decide(text,text,uuid,text),bri.approval_status(text,text,uuid) TO bri_app;
-- No role creation or hosted credential provisioning. By default execution is
-- inaccessible to the app. Offline, provision a dedicated restricted worker
-- and explicitly grant ONLY schema USAGE and this one function to it.
