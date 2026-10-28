-- docs/agent Agent중심-화면 AC-8: the prompt tokens a provider served from its prompt cache, kept apart from the prompt
-- tokens (which count them, as OpenAI counts them) so the cost can be priced by the cached input price. Null when the
-- provider reported none (and for every row written before this migration): unknown, which is not zero.
ALTER TABLE cost_ledger ADD COLUMN cached_prompt_tokens BIGINT;

-- The business agent's own model usage is a ledger row of its run too (kind AGENT_CHAT), apart from the engine's
-- decisions (CHAT) so a run's decision cost keeps meaning what it meant.
ALTER TABLE cost_ledger DROP CONSTRAINT cost_ledger_kind_chk;
ALTER TABLE cost_ledger ADD CONSTRAINT cost_ledger_kind_chk CHECK (kind IN ('CHAT', 'EMBEDDING', 'AGENT_CHAT'));
