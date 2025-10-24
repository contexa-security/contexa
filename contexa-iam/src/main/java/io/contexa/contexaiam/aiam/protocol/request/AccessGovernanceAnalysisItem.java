package io.contexa.contexaiam.aiam.protocol.request;

import lombok.Data;

@Data
public class AccessGovernanceAnalysisItem {
    private String auditScope;
    private String analysisType;
    private String query;
    private String priority = "NORMAL";
    private boolean enableDormantPermissionAnalysis = true;
    private boolean enableExcessivePermissionDetection = true;
    private boolean enableSodViolationCheck = true;
}
