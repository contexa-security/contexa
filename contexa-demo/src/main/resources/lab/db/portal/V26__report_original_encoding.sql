alter table lab.experience_report
    add column payload_encoding varchar(32) not null default 'JSONB_REORDERED_V1';

alter table lab.experience_report alter column payload type text using payload::text;

alter table lab.experience_report alter column payload_encoding set default 'PRESERVED_JSON_V2';
