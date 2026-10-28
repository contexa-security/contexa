-- docs/agent Agent중심-화면 AC-4b: a combination of the agent menu may carry a choice of the delegation (the editable case's
-- quantity limit, period and allowed operations), so each choice keeps its own answer. A combination without a choice has
-- the empty key.
ALTER TABLE agent_menu ADD COLUMN choice_key VARCHAR(40) NOT NULL DEFAULT '';
ALTER TABLE agent_menu DROP CONSTRAINT agent_menu_pkey;
ALTER TABLE agent_menu ADD PRIMARY KEY (case_key, path, choice_key);
