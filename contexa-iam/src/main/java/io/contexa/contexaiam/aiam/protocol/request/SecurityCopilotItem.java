package io.contexa.contexaiam.aiam.protocol.request;

import lombok.Data;

import java.util.Map;

@Data
public class SecurityCopilotItem{
    private String securityQuery;
    private String analysisScope;
    private String userId;
    private String priority;
    private Map<String, Object> metadata;
    private String organizationId;
}
