-- A template principal answers the engine's identity check the way the employee would (approval Q-43, decided
-- 2026-10-07): it reads the one-time code from the demo inbox, enters it and sends the same request again. The step
-- keeps the check and the re-issued request, and the template the number of checks it passed, so a visitor sees that
-- the employee's usual pattern was learned with them. A step answered after a check is not learned by the engine (it
-- learns from ALLOW decisions only).
ALTER TABLE template_step ADD COLUMN identity_check_passed BOOLEAN;
ALTER TABLE template_step ADD COLUMN identity_check_reason VARCHAR(200);
ALTER TABLE template_step ADD COLUMN reissue_request_id UUID;
ALTER TABLE template_step ADD COLUMN reissue_status INTEGER;
ALTER TABLE template_step ADD COLUMN reissue_outcome VARCHAR(16);
ALTER TABLE engine_template ADD COLUMN identity_checks INTEGER NOT NULL DEFAULT 0;
