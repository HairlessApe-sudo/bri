-- No role creation, runtime credential or grants. The separate observer is a
-- read-only PROVIDER capability; its sole DB mutation is bounded evidence/state.
CREATE POLICY approval_permission_delete ON bri.role_permissions AS RESTRICTIVE FOR DELETE TO bri_app
USING (NOT starts_with(permission,'user:mfa_reset:'));
-- Cover cascading deletes via the legacy app_roles catalog as well as direct DML.
CREATE FUNCTION bri.guard_reset_permission_delete() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF session_user='bri_app' OR current_user='bri_app' THEN
        RAISE EXCEPTION 'platform-managed permission' USING ERRCODE='42501'; END IF;
    RETURN OLD;
END $$;
CREATE TRIGGER protect_reset_permission BEFORE DELETE ON bri.role_permissions FOR EACH ROW
WHEN (starts_with(OLD.permission,'user:mfa_reset:')) EXECUTE FUNCTION bri.guard_reset_permission_delete();
REVOKE ALL ON FUNCTION bri.guard_reset_permission_delete() FROM PUBLIC,bri_app;

ALTER TABLE bri.privileged_approvals ADD COLUMN sealed boolean NOT NULL DEFAULT false CHECK (NOT sealed OR state='FAILED'),
    ADD COLUMN retry_of uuid REFERENCES bri.privileged_approvals;
DROP INDEX bri.privileged_approval_one_open;
CREATE UNIQUE INDEX privileged_approval_one_open ON bri.privileged_approvals(tenant_id,action,target)
    WHERE state IN ('PENDING','APPROVED','EXECUTING','FAILED') AND NOT sealed;
ALTER TABLE bri.approval_events ALTER COLUMN actor DROP NOT NULL;
-- No person is impersonated in an observation audit. Correlation binds PLAN to
-- one pinned dispatch set at one point in time; no factor secrets or error text.
CREATE TABLE bri.approval_observations (
    correlation uuid NOT NULL,
    phase text NOT NULL CHECK (phase IN ('PLAN','RECORD')),
    approval_id uuid NOT NULL REFERENCES bri.privileged_approvals,
    pinned uuid[], dispatched uuid[] NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('PLAN','VERIFIED_ABSENT','UNRESOLVED','SAFE_HANDOFF','UNAVAILABLE')),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(correlation,phase)
);
ALTER TABLE bri.approval_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.approval_observations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON bri.approval_observations FROM PUBLIC,bri_app;
CREATE POLICY approval_observer_read ON bri.approval_observations FOR SELECT TO bri_migrator USING (true);
CREATE POLICY approval_observer_append ON bri.approval_observations FOR INSERT TO bri_migrator WITH CHECK (true);
CREATE TRIGGER immutable_observation BEFORE UPDATE OR DELETE OR TRUNCATE ON bri.approval_observations
FOR EACH STATEMENT EXECUTE FUNCTION bri.deny_audit_mutation();

CREATE FUNCTION bri.approval_observer_role() RETURNS boolean LANGUAGE sql STABLE
SET search_path=pg_catalog,pg_temp AS $$
    SELECT session_user='bri_approval_observer' AND EXISTS (SELECT FROM pg_roles r WHERE r.rolname=session_user
        AND r.rolcanlogin AND NOT (r.rolsuper OR r.rolinherit OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
        AND NOT EXISTS(SELECT FROM pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid AND NOT (
            pg_get_userbyid(m.member)='postgres' AND pg_get_userbyid(m.grantor)='supabase_admin'
            AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)))
$$;
CREATE FUNCTION bri.approval_observation_queue(after_id uuid, batch integer) RETURNS SETOF uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF NOT bri.approval_observer_role() OR batch IS NULL OR batch NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION 'observation denied' USING ERRCODE='42501'; END IF;
    RETURN QUERY SELECT approval_id FROM bri.privileged_approvals WHERE state IN ('EXECUTING','FAILED') AND NOT sealed
        AND (after_id IS NULL OR approval_id>after_id) ORDER BY approval_id LIMIT batch;
END $$;
CREATE FUNCTION bri.approval_observe(a uuid,op text,cid uuid,present uuid[],verified uuid[])
RETURNS TABLE(stage text,auth_target uuid,issuer text) LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE r bri.privileged_approvals; plan bri.approval_observations; sent uuid[]; src text; result text; st text;
BEGIN
    IF NOT bri.approval_observer_role() OR a IS NULL OR cid IS NULL OR op IS NULL OR op NOT IN ('PLAN','RECORD','UNAVAILABLE') THEN
        RAISE EXCEPTION 'observation denied' USING ERRCODE='42501'; END IF;
    IF NOT pg_try_advisory_xact_lock(hashtextextended(a::text,1010)) THEN
        RAISE EXCEPTION 'approval busy' USING ERRCODE='55P03'; END IF;
    PERFORM bri.approval_lock();
    SELECT * INTO STRICT r FROM bri.privileged_approvals WHERE approval_id=a FOR UPDATE;
    IF r.state='COMPLETED' OR r.sealed THEN RETURN QUERY SELECT r.state,NULL::uuid,NULL::text; RETURN; END IF;
    SELECT co.auth_issuer INTO src FROM bri.credential_operations co JOIN bri.auth_identity_links i
        ON (i.auth_user_id,i.principal_id,i.auth_issuer)=(co.auth_user_id,co.principal_id,co.auth_issuer)
        WHERE co.operation_id=a AND co.kind='factor_reenrollment' AND co.confirmed_at IS NULL
          AND (co.principal_id,co.auth_user_id)=(r.target,r.target_auth) AND i.provider_type='native' AND i.auth_subject=r.target_auth::text;
    IF src IS NULL OR r.state NOT IN ('EXECUTING','FAILED') THEN RAISE EXCEPTION 'observation conflict' USING ERRCODE='55000'; END IF;
    sent:=ARRAY(SELECT factor_id FROM bri.approval_dispatches WHERE approval_id=a ORDER BY factor_id);
    IF op='PLAN' THEN
        INSERT INTO bri.approval_observations(correlation,phase,approval_id,pinned,dispatched,outcome)
            VALUES(cid,'PLAN',a,r.factor_ids,sent,'PLAN') ON CONFLICT DO NOTHING;
    END IF;
    SELECT * INTO STRICT plan FROM bri.approval_observations WHERE correlation=cid AND phase='PLAN';
    IF (plan.approval_id,plan.pinned,plan.dispatched) IS DISTINCT FROM (a,r.factor_ids,sent)
        OR plan.occurred_at < clock_timestamp()-interval '1 minute' THEN
        RAISE EXCEPTION 'observation changed' USING ERRCODE='55000'; END IF;
    IF op='PLAN' THEN RETURN QUERY SELECT r.state,r.target_auth,src; RETURN; END IF;
    IF EXISTS(SELECT FROM bri.approval_observations WHERE correlation=cid AND phase='RECORD') THEN
        RETURN QUERY SELECT r.state,NULL::uuid,NULL::text; RETURN; END IF;
    IF op='UNAVAILABLE' THEN result:='UNAVAILABLE';
    ELSE
        IF present IS NULL OR verified IS NULL OR cardinality(present)>256 OR cardinality(verified)>256
           OR cardinality(present)<>(SELECT count(DISTINCT fid) FROM unnest(present) fid)
           OR cardinality(verified)<>(SELECT count(DISTINCT fid) FROM unnest(verified) fid)
           OR NOT verified <@ present THEN RAISE EXCEPTION 'invalid observation'; END IF;
        -- Absence means not in the complete inventory (not merely unverified).
        UPDATE bri.approval_dispatches SET absent_at=clock_timestamp() WHERE approval_id=a AND absent_at IS NULL
            AND NOT factor_id=ANY(present);
        IF r.factor_ids IS NOT NULL AND r.factor_ids <@ sent AND NOT r.factor_ids && present AND cardinality(verified)=0 THEN
            result:='VERIFIED_ABSENT';
        ELSIF NOT sent && present AND cardinality(verified)>0 THEN result:='SAFE_HANDOFF';
        ELSE result:='UNRESOLVED'; END IF;
    END IF;
    -- An unknown in-flight delete is NEVER freed for redispatch. A replacement
    -- or undispatched factor needs a wholly new, two-person authorization.
    st:=CASE WHEN result='VERIFIED_ABSENT' THEN 'COMPLETED' ELSE 'FAILED' END;
    INSERT INTO bri.approval_observations(correlation,phase,approval_id,pinned,dispatched,outcome)
        VALUES(cid,'RECORD',a,r.factor_ids,sent,result);
    UPDATE bri.privileged_approvals SET state=st,sealed=(result='SAFE_HANDOFF') WHERE approval_id=a;
    IF r.state<>st OR result='SAFE_HANDOFF' THEN
        PERFORM set_config('bri.correlation_id',cid::text,true);
        PERFORM bri.approval_event(a,NULL,st);
    END IF;
    RETURN QUERY SELECT st,NULL::uuid,NULL::text;
END $$;
REVOKE ALL ON FUNCTION bri.approval_observer_role(),bri.approval_observe(uuid,text,uuid,uuid[],uuid[]),
    bri.approval_observation_queue(uuid,integer) FROM PUBLIC,bri_app;

-- A provider factor UUID is immutable for its native user. Even a later fresh
-- approval may not consume a second permit for an already dispatched factor.
-- approval_work takes the shared governance fence before every dispatch.
CREATE FUNCTION bri.approval_unique_factor_dispatch() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF EXISTS (SELECT FROM bri.approval_dispatches d JOIN bri.privileged_approvals prior USING(approval_id)
        JOIN bri.privileged_approvals fresh ON fresh.target_auth=prior.target_auth
        WHERE fresh.approval_id=NEW.approval_id AND prior.approval_id<>fresh.approval_id AND d.factor_id=NEW.factor_id) THEN
        RAISE EXCEPTION 'factor permit already consumed' USING ERRCODE='55000'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER approval_one_factor_permit BEFORE INSERT ON bri.approval_dispatches
FOR EACH ROW EXECUTE FUNCTION bri.approval_unique_factor_dispatch();
REVOKE ALL ON FUNCTION bri.approval_unique_factor_dispatch() FROM PUBLIC,bri_app;

-- A sealed operation never dispatches again. Link fresh requests to the
-- original quarantine; its credential-operation ID changes only on fresh dual
-- authorization, in one transaction (never a session-unblock gap). Old rows,
-- votes, receipts, timestamps and provenance remain in the approval histories.
CREATE FUNCTION bri.approval_retry_parent(t text,p uuid) RETURNS uuid LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
    SELECT r.approval_id FROM bri.privileged_approvals r JOIN bri.credential_operations co ON co.operation_id=r.approval_id
      WHERE r.tenant_id=t AND r.target=p AND r.sealed AND r.action='USER_MFA_RESET' AND co.kind='factor_reenrollment'
        AND co.confirmed_at IS NULL AND (co.principal_id,co.auth_user_id)=(p,r.target_auth)
        AND co.auth_issuer=current_setting('bri.auth_issuer',true)
$$;
CREATE POLICY approval_transfer_quarantine ON bri.credential_operations FOR UPDATE TO bri_migrator
    USING (kind='factor_reenrollment' AND confirmed_at IS NULL) WITH CHECK (kind='factor_reenrollment' AND confirmed_at IS NULL);
-- Preserve every 0012 check on confirmation; allow ONLY a pending-to-pending
-- handoff to the new already dual-approved operation, by the original worker.
DO $proof_policy$
DECLARE existing_check text;
BEGIN
    SELECT pg_get_expr(polwithcheck,polrelid) INTO STRICT existing_check FROM pg_policy
      WHERE polrelid='bri.credential_operations'::regclass AND polname='require_reenrollment_proof';
    EXECUTE format('ALTER POLICY require_reenrollment_proof ON bri.credential_operations WITH CHECK ((%s) OR
        (confirmed_at IS NULL AND kind=''factor_reenrollment'' AND session_user=''bri_approval_worker'' AND EXISTS (
            SELECT FROM bri.privileged_approvals fresh JOIN bri.privileged_approvals old ON old.approval_id=fresh.retry_of
            WHERE fresh.approval_id=credential_operations.operation_id AND fresh.state=''APPROVED'' AND old.sealed
              AND fresh.target=old.target AND fresh.target_auth=old.target_auth AND fresh.tenant_id=old.tenant_id
              AND fresh.target=credential_operations.principal_id AND fresh.target_auth=credential_operations.auth_user_id)))',existing_check);
END $proof_policy$;
CREATE FUNCTION bri.approval_transfer_quarantine(old_id uuid,new_id uuid,p uuid,u uuid) RETURNS void LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM bri.lock_session_guard(p);
    UPDATE bri.credential_operations SET operation_id=new_id,reserved_at=clock_timestamp()
      WHERE operation_id=old_id AND principal_id=p AND auth_user_id=u AND kind='factor_reenrollment' AND confirmed_at IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'quarantine mismatch'; END IF;
END $$;
REVOKE ALL ON FUNCTION bri.approval_retry_parent(text,uuid),bri.approval_transfer_quarantine(uuid,uuid,uuid,uuid) FROM PUBLIC,bri_app;
DO $upgrade$
DECLARE fn regprocedure; before_sql text; after_sql text; defn text;
BEGIN
    FOR fn,before_sql,after_sql IN VALUES
      ('bri.approval_request(text,text,uuid,text,uuid)'::regprocedure,
       'bri.approval_target(t,target_id,false)', 'bri.approval_target(t,target_id,bri.approval_retry_parent(t,target_id) IS NOT NULL)'),
      ('bri.approval_request(text,text,uuid,text,uuid)'::regprocedure,
       'requester,reason,state,created_at,expires_at)', 'requester,reason,state,created_at,expires_at,retry_of)'),
      ('bri.approval_request(text,text,uuid,text,uuid)'::regprocedure,
       $old$stamp+interval '24 hours');$old$, $new$stamp+interval '24 hours',bri.approval_retry_parent(t,target_id));$new$),
      ('bri.approval_decide(text,text,uuid,text)'::regprocedure,
       'bri.approval_target(t,r.target,false)','bri.approval_target(t,r.target,r.retry_of IS NOT NULL)'),
      ('bri.approval_guard_target_change()'::regprocedure,
       $old$r.state IN ('EXECUTING','FAILED')$old$,
       $new$r.state IN ('EXECUTING','FAILED') AND (NOT r.sealed OR EXISTS (SELECT FROM bri.credential_operations co
           WHERE co.operation_id=r.approval_id AND co.confirmed_at IS NULL))$new$),
      ('bri.approval_work(text,text,uuid,text,uuid[])'::regprocedure,
       $old$IF op='STATUS' THEN$old$, $new$IF r.sealed OR op='STATUS' THEN$new$),
      ('bri.approval_work(text,text,uuid,text,uuid[])'::regprocedure,
       $old$bri.approval_target(t,r.target,r.state<>'APPROVED')$old$, $new$bri.approval_target(t,r.target,r.retry_of IS NOT NULL OR r.state<>'APPROVED')$new$),
      ('bri.approval_work(text,text,uuid,text,uuid[])'::regprocedure,
       'IF bri.reserve_factor_reenrollment(',
       $new$IF r.retry_of IS NOT NULL THEN
                IF r.retry_of IS DISTINCT FROM bri.approval_retry_parent(t,r.target) THEN RAISE EXCEPTION 'quarantine mismatch'; END IF;
                PERFORM bri.approval_transfer_quarantine(r.retry_of,a,r.target,r.target_auth);
            ELSIF bri.reserve_factor_reenrollment($new$)
    LOOP
        defn:=pg_get_functiondef(fn);
        IF cardinality(string_to_array(defn,before_sql))<>2 THEN RAISE EXCEPTION 'unexpected approval definition: %',fn; END IF;
        EXECUTE replace(defn,before_sql,after_sql);
    END LOOP;
END $upgrade$;
