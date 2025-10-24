package io.contexa.contexacore.soar.approval;

import java.io.Serializable;
import java.util.Map;

public record ApprovalRequestDetails(
        String actionName,
        String actionType,
        String riskLevel,
        String description,
        String arguments,
        Map<String, Object> parameters) implements Serializable {}