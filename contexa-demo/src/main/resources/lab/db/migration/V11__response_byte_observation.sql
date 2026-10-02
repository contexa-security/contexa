ALTER TABLE lab.business_http_observation ADD COLUMN servlet_output_bytes bigint
    CHECK (servlet_output_bytes IS NULL OR servlet_output_bytes >= 0);
ALTER TABLE lab.business_http_observation ADD COLUMN output_capture_state varchar(40);
