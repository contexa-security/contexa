-- V2: Partition expansion and constraint fixes
-- Addresses: expired partitions (2025-03 limit), UNIQUE constraint without partition key, pgcrypto extension

-- Ensure pgcrypto is available for gen_random_uuid() on PostgreSQL < 13
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Fix UNIQUE constraint: must include partition key (executed_at) for partitioned tables
ALTER TABLE tool_execution_history DROP CONSTRAINT IF EXISTS tool_execution_history_execution_id_key;
ALTER TABLE tool_execution_history ADD CONSTRAINT tool_execution_history_exec_uniq UNIQUE (execution_id, executed_at);

-- Add partitions for 2025-04 through 2026-12
CREATE TABLE IF NOT EXISTS tool_execution_history_2025_04 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2025_05 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2025-05-01') TO ('2025-06-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2025_06 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2025-06-01') TO ('2025-07-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2025_07 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2025-07-01') TO ('2025-08-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2025_08 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2025-08-01') TO ('2025-09-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2025_09 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2025_10 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2025_11 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2025_12 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2026_01 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2026_02 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2026_03 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2026_04 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2026_05 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2026_06 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2026_07 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2026_08 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2026_09 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2026_10 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2026_11 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');

CREATE TABLE IF NOT EXISTS tool_execution_history_2026_12 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
