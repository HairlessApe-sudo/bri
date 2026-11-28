-- Require a current revision for either new correction decision.
CREATE OR REPLACE FUNCTION bri.km_review_correction(t text,actor uuid,sub uuid,sid uuid,issuer text,record_id uuid,version uuid,
    proposal_id uuid,action text,request_id uuid,correlation uuid,fmt text) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE p bri.knowledge_metadata_correction_proposals; d bri.knowledge_metadata_correction_decisions; revised bigint;
DECLARE permission constant text := 'knowledge:metadata:review';
BEGIN
    IF bri.km_correction_node(t,actor,sub,sid,issuer,record_id,version,fmt,permission) IS NULL THEN RETURN NULL; END IF;
    PERFORM bri.xlsx_lock_actor(actor,sub,sid);
    IF bri.km_correction_node(t,actor,sub,sid,issuer,record_id,version,fmt,permission) IS NULL THEN RETURN NULL; END IF;
    SELECT x.* INTO p FROM bri.knowledge_metadata_correction_proposals x
    WHERE (x.tenant_id,x.format,x.job_id,x.record_id,x.proposal_id)=(t,fmt,version,$6,$8) AND x.proposer_id<>actor;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF request_id IS NULL OR correlation IS NULL OR NOT coalesce(action IN ('approve','reject'),false) THEN
        RAISE EXCEPTION 'Invalid metadata correction decision' USING ERRCODE='22023';
    END IF;
    SELECT x.* INTO d FROM bri.knowledge_metadata_correction_decisions x
    WHERE (x.tenant_id,x.format,x.job_id,x.proposal_id)=(t,fmt,version,$8);
    IF FOUND THEN
        IF (d.reviewer_id,d.request_id,d.decision) IS DISTINCT FROM (actor,request_id,action) THEN
            RAISE EXCEPTION 'Metadata correction decision conflict' USING ERRCODE='23505';
        END IF;
    ELSE
        -- Both new decisions require the proposal's revision under the existing
        -- fence; an authorized exact terminal replay above is not a new decision.
        IF bri.km_current_revision(t,fmt,version) <> p.expected_revision THEN
            RAISE EXCEPTION 'Metadata revision conflict' USING ERRCODE='23505';
        END IF;
        IF action='approve' THEN
            revised := p.expected_revision+1;
            PERFORM bri.km_revision(t,fmt,version,record_id,revised,p.payload_id);
        END IF;
        INSERT INTO bri.knowledge_metadata_correction_decisions
            (tenant_id,format,job_id,proposal_id,proposer_id,reviewer_id,request_id,correlation,decision,metadata_revision)
        VALUES (t,fmt,version,proposal_id,p.proposer_id,actor,request_id,correlation,action,revised) RETURNING * INTO d;
        IF bri.km_correction_node(t,actor,sub,sid,issuer,record_id,version,fmt,permission) IS NULL THEN
            RAISE EXCEPTION 'Metadata correction lost authority' USING ERRCODE='42501';
        END IF;
    END IF;
    RETURN jsonb_build_object('record_id',record_id,'source_version_id',version,
        'proposal_id',d.proposal_id,'decision',d.decision,'metadata_revision',d.metadata_revision::text);
END $$;
