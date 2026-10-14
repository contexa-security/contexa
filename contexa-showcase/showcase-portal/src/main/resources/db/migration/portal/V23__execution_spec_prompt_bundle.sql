-- The security decision prompt bundle control D runs (docs/showcase/프롬프트-최종-구현계획.md LU-6, P3 extra 46): two
-- measurements of different bundles on the same code were one measurement setting. Null for specifications recorded
-- before control D reported it, so their hashes stay as they were.
ALTER TABLE execution_spec ADD COLUMN prompt_bundle VARCHAR(64);
