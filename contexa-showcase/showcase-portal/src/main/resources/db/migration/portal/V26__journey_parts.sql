-- The redesigned flow (docs/showcase/화면재편-구현계획.md P-1): one route, and the place is the start (0) or one of
-- five parts (1-5). A journey kept on the concept path continues on the one route.
UPDATE visitor_journey SET route = 'DEFAULT' WHERE route <> 'DEFAULT';
ALTER TABLE visitor_journey DROP CONSTRAINT visitor_journey_route_chk;
ALTER TABLE visitor_journey ADD CONSTRAINT visitor_journey_route_chk CHECK (route = 'DEFAULT');
ALTER TABLE visitor_journey DROP CONSTRAINT visitor_journey_act_chk;
ALTER TABLE visitor_journey ADD CONSTRAINT visitor_journey_act_chk CHECK (act BETWEEN 0 AND 5);
