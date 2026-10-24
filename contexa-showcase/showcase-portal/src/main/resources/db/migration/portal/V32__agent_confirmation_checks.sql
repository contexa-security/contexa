-- docs/agent DD-27: the operator's checks of a confirmation (A5 carried over to A7): the delegating person's own
-- request sent after the person reported the agent or left the confirmation unanswered (the person's work goes on
-- while the agent's is stopped), and the agent's request sent again and again while it waits (the call limit, A5-7).
ALTER TABLE run_agent_confirmation ADD COLUMN person_request JSONB;
ALTER TABLE run_agent_confirmation ADD COLUMN retries JSONB;
