-- The final screen design (docs/showcase/최종화면-구현계획.md F0-1): the main flow is six groups, so the place is
-- before the first (0) or one of the groups 1-6. A place kept from the flow before stays as it is until the visitor's
-- next screen reports its own.
ALTER TABLE visitor_journey DROP CONSTRAINT visitor_journey_act_chk;
ALTER TABLE visitor_journey ADD CONSTRAINT visitor_journey_act_chk CHECK (act BETWEEN 0 AND 6);
