-- Template currency and retention of retired material (docs/showcase/계획대조-검수.md N-7, N-8).

-- The versions a template was learned under (TemplateVersions: code, engine, mode, protection, models, time zone and
-- company data). A run clones only a template learned under the versions in force; NULL marks a template from before
-- this column and is never current.
ALTER TABLE engine_template ADD COLUMN learned_under CHAR(64);
ALTER TABLE engine_template ADD COLUMN retired_at TIMESTAMPTZ;

CREATE INDEX engine_template_current_idx ON engine_template (employee_key, status, learned_under, ready_at DESC);

-- When a published recording was replaced; retired and old draft recordings are deleted after the retention period.
ALTER TABLE replay_record ADD COLUMN retired_at TIMESTAMPTZ;

UPDATE replay_record SET retired_at = now() WHERE status = 'RETIRED';

-- One READY template per employee: older READY templates become RETIRED, as a newly learned template now does.
UPDATE engine_template t
   SET status = 'RETIRED', retired_at = now()
 WHERE t.status = 'READY'
   AND EXISTS (SELECT 1 FROM engine_template n
                WHERE n.employee_key = t.employee_key AND n.status = 'READY' AND n.ready_at > t.ready_at);
