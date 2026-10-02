ALTER TABLE lab.model_boundary_observation
    ADD COLUMN request_id uuid,
    ADD COLUMN event_id varchar(200),
    ADD COLUMN processing_generation varchar(500),
    ADD COLUMN pipeline_request_id varchar(200);
CREATE INDEX model_boundary_request_idx ON lab.model_boundary_observation (request_id, observed_at, id)
    WHERE request_id IS NOT NULL;
COMMENT ON TABLE lab.model_boundary_observation IS
    'ChatClient advisor boundary. Explicit native references only for new linked observations; older rows remain unlinked. Not provider HTTP wire evidence.';
