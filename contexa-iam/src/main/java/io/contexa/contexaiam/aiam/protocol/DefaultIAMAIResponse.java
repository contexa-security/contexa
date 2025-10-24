package io.contexa.contexaiam.aiam.protocol;

import io.contexa.contexacommon.domain.response.IAMResponse;

public class DefaultIAMAIResponse extends IAMResponse {
    private final String data;
    private final long executionTimeMs;
    private final String status;
    private final String organizationId;
    private final String domain;

    public DefaultIAMAIResponse(String requestId, String data, long executionTimeMs,
                                String status, String organizationId, String domain) {
        super(requestId, ExecutionStatus.SUCCESS);
        this.data = data;
        this.executionTimeMs = executionTimeMs;
        this.status = status;
        this.organizationId = organizationId;
        this.domain = domain;
    }

    @Override
    public Object getData() {
        return data;
    }

    @Override
    public String getResponseType() {
        return "IAM_RESPONSE";
    }

    public long getExecutionTimeMs() {
        return executionTimeMs;
    }

    public String getExecutionStatus() {
        return status;
    }

    public String getOrganizationId() {
        return organizationId;
    }

    public String getDomain() {
        return domain;
    }
}
