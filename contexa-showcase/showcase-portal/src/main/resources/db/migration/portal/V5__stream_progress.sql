-- How far a streamed export got over time (deck p.11, P3-BE-02): announced total, delivered items, first and last
-- line, the engine's cut action and [ms since sent, delivered items] samples. Null for other operations.
ALTER TABLE run_arm_result ADD COLUMN stream JSONB;
