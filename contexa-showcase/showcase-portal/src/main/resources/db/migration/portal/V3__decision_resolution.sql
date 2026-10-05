-- The engine records a response contract failure as parser_failure and other technical failures as
-- technical_fallback (AiSecurityDecisionObservationWriter). Both, and an unsuccessful analysis, are unresolved:
-- counted apart, never as a decision (deck p.24).
ALTER TABLE run_decision ADD COLUMN parser_failure BOOLEAN;
ALTER TABLE run_decision ADD COLUMN unresolved BOOLEAN;
ALTER TABLE template_step ADD COLUMN unresolved BOOLEAN;
ALTER TABLE engine_template ADD COLUMN stopped_at_step INTEGER;
