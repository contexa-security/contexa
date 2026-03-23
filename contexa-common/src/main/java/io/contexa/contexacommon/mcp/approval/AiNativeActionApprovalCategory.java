package io.contexa.contexacommon.mcp.approval;

import org.springframework.util.StringUtils;

import java.util.Arrays;

public enum AiNativeActionApprovalCategory {
    STANDARD_MUTATION(false),
    DESTRUCTIVE_TOOL(true),
    PRIVILEGED_EXPORT(true),
    CONNECTOR_RECONFIGURATION(true);

    private final boolean explicitApprovalRequired;

    AiNativeActionApprovalCategory(boolean explicitApprovalRequired) {
        this.explicitApprovalRequired = explicitApprovalRequired;
    }

    public boolean explicitApprovalRequired() {
        return explicitApprovalRequired;
    }

    public static AiNativeActionApprovalCategory fromValue(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        return Arrays.stream(values())
                .filter(item -> item.name().equalsIgnoreCase(value.trim()))
                .findFirst()
                .orElse(null);
    }
}