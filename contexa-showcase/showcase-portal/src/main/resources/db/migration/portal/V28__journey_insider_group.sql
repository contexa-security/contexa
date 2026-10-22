-- The insider group (docs/showcase/최종화면-구현계획.md IN-6 확정 설계): the main flow is seven groups, the insider group
-- coming fifth, so the place is before the first (0) or one of the groups 1-7. A place kept in the groups that moved (the
-- comparison, fifth until now, and the summary, sixth until now) moves with them.
ALTER TABLE visitor_journey DROP CONSTRAINT visitor_journey_act_chk;
UPDATE visitor_journey SET act = act + 1 WHERE act >= 5;
ALTER TABLE visitor_journey ADD CONSTRAINT visitor_journey_act_chk CHECK (act BETWEEN 0 AND 7);
