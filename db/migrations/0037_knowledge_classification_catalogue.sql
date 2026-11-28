-- A19.1 local staged tenant catalogue. No implicit seed, role provisioning,
-- release EXECUTE grants, node/class ACLs, or knowledge associations.
CREATE TABLE bri.knowledge_classification_categories (
    tenant_id text NOT NULL REFERENCES bri.tenants,
    category_id text NOT NULL CHECK (category_id COLLATE "C" ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
    label text NOT NULL CHECK (octet_length(label) BETWEEN 1 AND 160 AND btrim(label) <> ''),
    PRIMARY KEY (tenant_id, category_id)
);

CREATE TABLE bri.knowledge_classifications (
    tenant_id text NOT NULL,
    classification_id text NOT NULL CHECK (classification_id COLLATE "C" ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
    category_id text NOT NULL,
    label text NOT NULL CHECK (octet_length(label) BETWEEN 1 AND 160 AND btrim(label) <> ''),
    description text CHECK (octet_length(description) <= 2048),
    retired_at timestamptz,
    PRIMARY KEY (tenant_id, classification_id),
    FOREIGN KEY (tenant_id, category_id) REFERENCES bri.knowledge_classification_categories
);

CREATE FUNCTION bri.classification_catalogue_socket() RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
    SELECT session_user='bri_classification_catalogue' AND inet_server_addr() IS NULL
        AND current_setting('listen_addresses')='';
$$;

ALTER TABLE bri.knowledge_classification_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.knowledge_classification_categories FORCE ROW LEVEL SECURITY;
ALTER TABLE bri.knowledge_classifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.knowledge_classifications FORCE ROW LEVEL SECURITY;
REVOKE ALL ON bri.knowledge_classification_categories, bri.knowledge_classifications FROM PUBLIC, bri_app;

-- Only the table-owning definer executing under the private transport can
-- select/write. The transport itself has no table rights. No DELETE policy.
CREATE POLICY classification_category_select ON bri.knowledge_classification_categories
    FOR SELECT TO bri_migrator USING (bri.classification_catalogue_socket());
CREATE POLICY classification_category_seed ON bri.knowledge_classification_categories
    FOR INSERT TO bri_migrator WITH CHECK (bri.classification_catalogue_socket());
CREATE POLICY classification_select ON bri.knowledge_classifications
    FOR SELECT TO bri_migrator USING (bri.classification_catalogue_socket());
CREATE POLICY classification_insert ON bri.knowledge_classifications
    FOR INSERT TO bri_migrator WITH CHECK (bri.classification_catalogue_socket() AND retired_at IS NULL);
CREATE POLICY classification_update ON bri.knowledge_classifications
    FOR UPDATE TO bri_migrator USING (bri.classification_catalogue_socket() AND retired_at IS NULL)
    WITH CHECK (bri.classification_catalogue_socket());
CREATE POLICY classification_catalogue_bound_issuer ON bri.provider_event_source
    FOR SELECT TO bri_migrator USING (bri.classification_catalogue_socket());

-- Native grants/catalogue permissions are already non-writable to bri_app
-- (0021). Prevent topology promotion even for a scoped catalogue assignment.
-- The existing statement-level org_nodes trigger takes the governance fence.
CREATE FUNCTION bri.guard_classification_catalogue_root() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE old_tenant text; new_tenant text;
BEGIN
    IF TG_OP='UPDATE' AND (OLD.tenant_id,OLD.node_id,OLD.node_type,OLD.parent_node_id IS NULL)
        IS NOT DISTINCT FROM (NEW.tenant_id,NEW.node_id,NEW.node_type,NEW.parent_node_id IS NULL) THEN
        RETURN NEW;
    END IF;
    IF TG_OP<>'INSERT' AND OLD.parent_node_id IS NULL THEN old_tenant := OLD.tenant_id; END IF;
    IF TG_OP<>'DELETE' AND NEW.parent_node_id IS NULL THEN new_tenant := NEW.tenant_id; END IF;
    IF EXISTS (SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions rp USING (tenant_id,role_id)
               WHERE a.tenant_id IN (old_tenant,new_tenant) AND a.status='active'
                 AND rp.permission='classification:catalogue:manage') THEN
        RAISE EXCEPTION 'classification catalogue root topology is protected' USING ERRCODE='42501';
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;

-- Keep the existing root guard's precedence when both grants are present.
CREATE TRIGGER zz_classification_catalogue_root_topology BEFORE INSERT OR UPDATE OR DELETE ON bri.org_nodes
FOR EACH ROW EXECUTE FUNCTION bri.guard_classification_catalogue_root();

CREATE FUNCTION bri.classification_catalogue_manager(t text, actor uuid, sub uuid, sid uuid, issuer text)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
    SELECT EXISTS (SELECT FROM bri.provider_event_source src WHERE src.issuer=$5)
      AND EXISTS (SELECT FROM bri.client_activation a JOIN bri.tenant_admin_policies ap USING (tenant_id)
                  WHERE a.tenant_id=$1 AND (SELECT count(*) FROM bri.governance_eligible e WHERE e.tenant_id=$1)
                        >= ap.min_emergency_admins)
      AND EXISTS (
        SELECT FROM bri.auth_sessions s JOIN bri.auth_identity_links i USING (auth_user_id,principal_id)
        JOIN bri.auth_principals p USING (principal_id) JOIN bri.auth_tenant_memberships m USING (principal_id)
        LEFT JOIN bri.session_guards g USING (principal_id)
        WHERE (s.principal_id,s.auth_user_id,s.session_id,m.tenant_id)=($2,$3,$4,$1)
          AND i.auth_issuer=$5 AND i.auth_subject=$3::text AND i.status='active' AND i.provider_type='native'
          AND s.revoked_at IS NULL AND s.started_at<=clock_timestamp()
          AND clock_timestamp()<least(s.expires_at,s.started_at+interval '8 hours')
          AND s.started_at>coalesce(g.primary_after,'-infinity'::timestamptz)
          AND p.status='active' AND p.deletion_requested_at IS NULL AND m.status='active'
          AND m.membership_type IN ('user','superuser','admin')
          AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships x WHERE x.principal_id=$2 AND x.tenant_id<>$1)
          AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id=$2)
          AND NOT EXISTS (SELECT FROM bri.credential_operations c WHERE c.principal_id=$2 AND c.confirmed_at IS NULL)
      ) AND EXISTS (
        SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions rp USING (tenant_id,role_id)
        JOIN bri.org_nodes n ON (n.tenant_id,n.node_id)=(a.tenant_id,a.scope_node_id)
        WHERE (a.tenant_id,a.principal_id,rp.permission)=($1,$2,'classification:catalogue:manage')
          AND a.status='active' AND n.node_type='root' AND n.parent_node_id IS NULL
          AND NOT EXISTS (SELECT FROM bri.org_nodes o WHERE o.tenant_id=n.tenant_id
                          AND o.parent_node_id IS NULL AND o.node_id<>n.node_id)
      );
$$;

CREATE FUNCTION bri.classification_catalogue_lock_manager(t text, actor uuid, sub uuid, sid uuid, issuer text)
RETURNS void LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF NOT bri.classification_catalogue_socket()
       OR NOT bri.classification_catalogue_manager(t,actor,sub,sid,issuer) THEN
        RAISE EXCEPTION 'Classification catalogue denied' USING ERRCODE='42501';
    END IF;
    -- Same governance -> session guard -> session order as protected XLSX.
    -- Recheck after waiting, using a fresh READ COMMITTED snapshot.
    PERFORM bri.xlsx_lock_actor(actor,sub,sid);
    IF NOT bri.classification_catalogue_manager(t,actor,sub,sid,issuer) THEN
        RAISE EXCEPTION 'Classification catalogue denied' USING ERRCODE='42501';
    END IF;
END $$;

CREATE FUNCTION bri.classification_catalogue_list(t text, actor uuid, sub uuid, sid uuid, issuer text,
                                                 node text, operation text)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF NOT bri.classification_catalogue_socket() THEN
        RAISE EXCEPTION 'Classification catalogue denied' USING ERRCODE='42501';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'Classification catalogue requires read committed' USING ERRCODE='25001';
    END IF;
    IF (CASE operation
        WHEN 'admin' THEN node IS NULL AND bri.classification_catalogue_manager(t,actor,sub,sid,issuer)
        WHEN 'csv_submit' THEN bri.csv_has_authority(t,actor,sub,sid,issuer,node,'source:submit')
        WHEN 'xlsx_submit' THEN bri.xlsx_has_authority(t,actor,sub,sid,issuer,node)
        WHEN 'csv_review' THEN bri.csv_has_authority(t,actor,sub,sid,issuer,node,'knowledge:review')
        WHEN 'xlsx_review' THEN bri.xlsx_governance_authorized(t,actor,sub,sid,issuer,node,'knowledge:review')
        ELSE false END) IS NOT TRUE THEN
        RAISE EXCEPTION 'Classification catalogue denied' USING ERRCODE='42501';
    END IF;
    RETURN (SELECT coalesce(jsonb_agg(jsonb_build_object(
                'category_id',c.category_id,'category_label',c.label,'classification_id',k.classification_id,
                'label',k.label,'description',k.description,'retired',k.retired_at IS NOT NULL)
                ORDER BY c.category_id COLLATE "C",k.classification_id COLLATE "C"),
                '[]'::jsonb)
            FROM bri.knowledge_classifications k JOIN bri.knowledge_classification_categories c USING (tenant_id,category_id)
            WHERE k.tenant_id=t AND (operation='admin' OR k.retired_at IS NULL));
END $$;

CREATE FUNCTION bri.classification_catalogue_seed(t text, actor uuid, sub uuid, sid uuid, issuer text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM bri.classification_catalogue_lock_manager(t,actor,sub,sid,issuer);
    INSERT INTO bri.knowledge_classification_categories(tenant_id,category_id,label)
    SELECT t,v.id,v.label FROM (VALUES
        ('governance','Governance'), ('operations','Operations'), ('technology','Technology'),
        ('strategy','Strategy'), ('finance','Finance'), ('risk','Risk'), ('experience','Experience'),
        ('organisation','Organisation'), ('general','General')
    ) v(id,label) ON CONFLICT (tenant_id,category_id) DO NOTHING;
    INSERT INTO bri.knowledge_classifications(tenant_id,category_id,classification_id,label)
    SELECT t,v.category,v.id,v.label FROM (VALUES
        ('governance','policy','Policy'), ('governance','regulation','Regulation'),
        ('governance','standard','Standard'), ('governance','decision-record','Decision record'),
        ('operations','process-description','Process description'), ('operations','procedure','Procedure'),
        ('operations','working-instruction','Working instruction'),
        ('technology','application','Application'), ('technology','infrastructure','Infrastructure'),
        ('technology','integration','Integration'), ('technology','technical-architecture','Technical architecture'),
        ('strategy','objective','Objective'), ('strategy','roadmap','Roadmap'), ('strategy','strategic-plan','Strategic plan'),
        ('finance','budget','Budget'), ('finance','contract','Contract'), ('finance','expenditure','Expenditure'),
        ('risk','risk','Risk'), ('risk','control','Control'), ('risk','assessment','Assessment'), ('risk','incident','Incident'),
        ('experience','historical-case','Historical case'), ('experience','lesson-learned','Lesson learned'),
        ('experience','evaluation','Evaluation'),
        ('organisation','responsibility','Responsibility'), ('organisation','capability','Capability'),
        ('organisation','service','Service'), ('general','reference-material','Reference material'),
        ('general','unclassified-knowledge','Unclassified knowledge')
    ) v(category,id,label) ON CONFLICT (tenant_id,classification_id) DO NOTHING;
END $$;

CREATE FUNCTION bri.classification_catalogue_create(t text, actor uuid, sub uuid, sid uuid, issuer text,
                                                   category text, id text, label text, description text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM bri.classification_catalogue_lock_manager(t,actor,sub,sid,issuer);
    INSERT INTO bri.knowledge_classifications(tenant_id,category_id,classification_id,label,description)
    VALUES (t,category,id,label,description);
END $$;

CREATE FUNCTION bri.classification_catalogue_rename(t text, actor uuid, sub uuid, sid uuid, issuer text,
                                                   id text, label text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM bri.classification_catalogue_lock_manager(t,actor,sub,sid,issuer);
    UPDATE bri.knowledge_classifications k SET label=$7 WHERE (k.tenant_id,k.classification_id)=(t,id)
        AND k.retired_at IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'Classification unavailable' USING ERRCODE='22023'; END IF;
END $$;

CREATE FUNCTION bri.classification_catalogue_describe(t text, actor uuid, sub uuid, sid uuid, issuer text,
                                                     id text, description text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM bri.classification_catalogue_lock_manager(t,actor,sub,sid,issuer);
    UPDATE bri.knowledge_classifications k SET description=$7 WHERE (k.tenant_id,k.classification_id)=(t,id)
        AND k.retired_at IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'Classification unavailable' USING ERRCODE='22023'; END IF;
END $$;

CREATE FUNCTION bri.classification_catalogue_retire(t text, actor uuid, sub uuid, sid uuid, issuer text, id text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM bri.classification_catalogue_lock_manager(t,actor,sub,sid,issuer);
    UPDATE bri.knowledge_classifications k SET retired_at=clock_timestamp() WHERE (k.tenant_id,k.classification_id)=(t,id)
        AND k.retired_at IS NULL;
    IF NOT FOUND AND NOT EXISTS (SELECT FROM bri.knowledge_classifications k WHERE (k.tenant_id,k.classification_id)=(t,id)) THEN
        RAISE EXCEPTION 'Classification unavailable' USING ERRCODE='22023';
    END IF;
END $$;

REVOKE ALL ON FUNCTION bri.classification_catalogue_socket(), bri.guard_classification_catalogue_root(),
    bri.classification_catalogue_manager(text,uuid,uuid,uuid,text),
    bri.classification_catalogue_lock_manager(text,uuid,uuid,uuid,text),
    bri.classification_catalogue_list(text,uuid,uuid,uuid,text,text,text),
    bri.classification_catalogue_seed(text,uuid,uuid,uuid,text),
    bri.classification_catalogue_create(text,uuid,uuid,uuid,text,text,text,text,text),
    bri.classification_catalogue_rename(text,uuid,uuid,uuid,text,text,text),
    bri.classification_catalogue_describe(text,uuid,uuid,uuid,text,text,text),
    bri.classification_catalogue_retire(text,uuid,uuid,uuid,text,text) FROM PUBLIC,bri_app;
