package io.contexa.contexacommon.soar.config;

public interface ToolApprovalPolicyManager {

    boolean isBlocked(String toolName);

    
    boolean requiresApproval(String toolName);

    
    int getApprovalTimeout(String toolName);
}
