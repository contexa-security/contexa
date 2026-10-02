ALTER TABLE lab.authentication_observation ADD COLUMN session_sha256 char(64);
CREATE INDEX authentication_observation_session_origin
    ON lab.authentication_observation (session_sha256, username, occurred_at DESC)
    WHERE request_method='POST' AND request_path='/login' AND authenticated_after=true;
