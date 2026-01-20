package io.contexa.contexacommon.soar.config;

import io.contexa.contexacommon.annotation.SoarTool;


public interface ToolApprovalPolicyManager {

    
    SoarTool.RiskLevel getRiskLevel(String toolName);

    
    boolean isBlocked(String toolName);

    
    boolean requiresApproval(String toolName);

    
    int getApprovalTimeout(String toolName);
}
