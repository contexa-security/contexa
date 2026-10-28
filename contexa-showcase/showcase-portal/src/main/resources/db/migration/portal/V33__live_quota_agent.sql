-- docs/agent Agent중심-화면 AC-2: a visitor's live runs are counted in points by their kind (a person's run 1, an agent's run
-- 3, a burst experience 5), and the agent runs a visitor starts in a day are counted on their own row: kind AGENT.
-- The rows of the kinds VISITOR and ADDRESS keep their meaning: with a person's run worth one point, their counts are
-- what they were.
ALTER TABLE live_quota DROP CONSTRAINT live_quota_kind_chk;
ALTER TABLE live_quota ADD CONSTRAINT live_quota_kind_chk CHECK (subject_kind IN ('VISITOR', 'ADDRESS', 'AGENT'));
