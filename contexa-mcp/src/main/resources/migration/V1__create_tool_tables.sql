-- Tool Metadata Table
-- 도구 메타데이터 저장
CREATE TABLE IF NOT EXISTS tool_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    version VARCHAR(50) DEFAULT '1.0.0',
    category VARCHAR(100),
    risk_level VARCHAR(20),
    approval_requirement VARCHAR(20),
    state VARCHAR(20) DEFAULT 'ACTIVE',
    input_schema TEXT,
    output_schema TEXT,
    required_permissions TEXT[],
    allowed_environments TEXT[],
    additional_properties JSONB,
    retryable BOOLEAN DEFAULT false,
    max_retries INTEGER DEFAULT 3,
    timeout_ms BIGINT DEFAULT 30000,
    audit_required BOOLEAN DEFAULT true,
    registered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_modified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    modified_by VARCHAR(255)
);

-- Indexes for tool_metadata
CREATE INDEX idx_tool_metadata_name ON tool_metadata(tool_name);
CREATE INDEX idx_tool_metadata_state ON tool_metadata(state);
CREATE INDEX idx_tool_metadata_category ON tool_metadata(category);
CREATE INDEX idx_tool_metadata_risk_level ON tool_metadata(risk_level);

-- Tool Execution History Table (Partitioned by date)
-- 도구 실행 이력 저장
CREATE TABLE IF NOT EXISTS tool_execution_history (
    id UUID DEFAULT gen_random_uuid(),
    execution_id VARCHAR(255) UNIQUE NOT NULL,
    tool_name VARCHAR(255) NOT NULL,
    request_data JSONB,
    response_data JSONB,
    execution_time_ms BIGINT,
    status VARCHAR(20),
    success BOOLEAN,
    error_message TEXT,
    error_type VARCHAR(100),
    executed_by VARCHAR(255),
    client_ip VARCHAR(45),
    user_agent TEXT,
    correlation_id VARCHAR(255),
    executed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, executed_at)
) PARTITION BY RANGE (executed_at);

-- Create partitions for the next 12 months
CREATE TABLE tool_execution_history_2025_01 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

CREATE TABLE tool_execution_history_2025_02 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');

CREATE TABLE tool_execution_history_2025_03 PARTITION OF tool_execution_history
    FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');

-- Indexes for tool_execution_history
CREATE INDEX idx_tool_execution_tool_name ON tool_execution_history(tool_name);
CREATE INDEX idx_tool_execution_status ON tool_execution_history(status);
CREATE INDEX idx_tool_execution_executed_by ON tool_execution_history(executed_by);
CREATE INDEX idx_tool_execution_executed_at ON tool_execution_history(executed_at);
CREATE INDEX idx_tool_execution_correlation_id ON tool_execution_history(correlation_id);

-- Approval Requests Table
-- 승인 요청 관리
CREATE TABLE IF NOT EXISTS approval_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id VARCHAR(255) UNIQUE NOT NULL,
    tool_name VARCHAR(255) NOT NULL,
    request_data JSONB,
    risk_level VARCHAR(20),
    requestor VARCHAR(255) NOT NULL,
    approvers TEXT[],
    current_approver VARCHAR(255),
    approval_level INTEGER DEFAULT 1,
    required_approvals INTEGER DEFAULT 1,
    status VARCHAR(20) DEFAULT 'PENDING',
    decision VARCHAR(20),
    reason TEXT,
    comments TEXT,
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(255)
);

-- Indexes for approval_requests
CREATE INDEX idx_approval_requests_tool_name ON approval_requests(tool_name);
CREATE INDEX idx_approval_requests_status ON approval_requests(status);
CREATE INDEX idx_approval_requests_requestor ON approval_requests(requestor);
CREATE INDEX idx_approval_requests_created_at ON approval_requests(created_at);

-- Tool Metrics Table
-- 도구 실행 메트릭
CREATE TABLE IF NOT EXISTS tool_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_name VARCHAR(255) NOT NULL,
    metric_type VARCHAR(50) NOT NULL,
    metric_value DECIMAL(20, 4),
    metric_unit VARCHAR(20),
    tags JSONB,
    recorded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for tool_metrics
CREATE INDEX idx_tool_metrics_tool_name ON tool_metrics(tool_name);
CREATE INDEX idx_tool_metrics_type ON tool_metrics(metric_type);
CREATE INDEX idx_tool_metrics_recorded_at ON tool_metrics(recorded_at);

-- Tool Orchestration Workflows Table
-- 도구 오케스트레이션 워크플로우
CREATE TABLE IF NOT EXISTS tool_workflows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    workflow_definition JSONB NOT NULL,
    version VARCHAR(50) DEFAULT '1.0.0',
    status VARCHAR(20) DEFAULT 'ACTIVE',
    created_by VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Workflow Execution History
CREATE TABLE IF NOT EXISTS workflow_execution_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID REFERENCES tool_workflows(id),
    workflow_name VARCHAR(255) NOT NULL,
    execution_context JSONB,
    steps_completed INTEGER DEFAULT 0,
    total_steps INTEGER,
    status VARCHAR(20),
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    executed_by VARCHAR(255),
    error_message TEXT
);

-- Indexes for workflow tables
CREATE INDEX idx_workflow_execution_workflow_id ON workflow_execution_history(workflow_id);
CREATE INDEX idx_workflow_execution_status ON workflow_execution_history(status);
CREATE INDEX idx_workflow_execution_started_at ON workflow_execution_history(started_at);

-- Tool Dependencies Table
-- 도구 간 의존성 관리
CREATE TABLE IF NOT EXISTS tool_dependencies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_name VARCHAR(255) NOT NULL,
    depends_on VARCHAR(255) NOT NULL,
    dependency_type VARCHAR(50) DEFAULT 'REQUIRED',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tool_name, depends_on)
);

-- Comments for tables
COMMENT ON TABLE tool_metadata IS 'Central registry for all security tools metadata';
COMMENT ON TABLE tool_execution_history IS 'Audit log of all tool executions partitioned by month';
COMMENT ON TABLE approval_requests IS 'Tracks approval requests for high-risk tool operations';
COMMENT ON TABLE tool_metrics IS 'Performance and usage metrics for tools';
COMMENT ON TABLE tool_workflows IS 'Orchestration workflow definitions';
COMMENT ON TABLE workflow_execution_history IS 'Execution history of orchestration workflows';
COMMENT ON TABLE tool_dependencies IS 'Dependencies between tools';