package io.contexa.contexacore.domain;

import java.util.List;

public record ApprovalPolicy(
        int requiredApprovers,
        List<String> requiredRoles,
        int timeoutMinutes,
        boolean autoApproveOnTimeout
) {}
