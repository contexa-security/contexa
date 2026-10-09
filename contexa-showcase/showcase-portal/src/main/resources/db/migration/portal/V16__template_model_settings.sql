-- The engine's model settings while a template was learned (docs/showcase/데모-재설계.md W1-3c): reasoning effort,
-- verbosity and output limit per layer, read from control D like the execution specification. The template version key
-- leaves them out on purpose (a change would force a relearning of 8 to 25 minutes per employee), so they are kept here.
ALTER TABLE engine_template ADD COLUMN model_settings JSONB;
