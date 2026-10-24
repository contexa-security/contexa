-- docs/agent A7-2e: the business agent's work of an agent task run: what the person asked, the agent's instruction
-- and model, every tool call with control D's answer and every control's outcome, the agent's answer, and what the work
-- proves per control (protected documents that left, where each control first stopped the work).
CREATE TABLE run_agent_task (
    run_id          VARCHAR(40)   PRIMARY KEY REFERENCES run (run_id) ON DELETE CASCADE,
    sender          VARCHAR(32)   NOT NULL,
    model           VARCHAR(64)   NOT NULL,
    system_prompt   TEXT          NOT NULL,
    instruction     TEXT          NOT NULL,
    tool_calls      JSONB         NOT NULL,
    final_answer    TEXT,
    stop_reason     VARCHAR(24)   NOT NULL,
    failure         VARCHAR(500),
    agent_usage     JSONB         NOT NULL,
    proof           JSONB         NOT NULL,
    started_at      TIMESTAMPTZ   NOT NULL,
    finished_at     TIMESTAMPTZ   NOT NULL
);
