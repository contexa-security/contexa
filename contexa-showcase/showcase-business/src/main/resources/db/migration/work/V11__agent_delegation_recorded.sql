-- Who wrote a delegation of record and when (docs/agent A2-10). Contexa states the record's author and its time against
-- the request, so that a record the acting agent wrote for itself reads apart from one the delegating person wrote.
-- recorded_by is an employee key or an agent id; both stay empty for a record that does not say.
ALTER TABLE agent_delegation ADD COLUMN recorded_by VARCHAR(120);
ALTER TABLE agent_delegation ADD COLUMN recorded_at TIMESTAMPTZ;
