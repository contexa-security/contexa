-- The address each learned activity was sent from (docs/showcase/데모-재설계.md 5A.1.2, W2-7). The field support
-- engineer worked the first learned week from a registered business trip, so the template learning replays those
-- requests from the trip network; NULL means the office network of the employee, as before this column.
ALTER TABLE scripted_activity ADD COLUMN client_ip VARCHAR(45);
