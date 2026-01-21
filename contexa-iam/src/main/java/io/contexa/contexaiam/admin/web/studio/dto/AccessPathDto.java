package io.contexa.contexaiam.admin.web.studio.dto;

import java.util.List;

public record AccessPathDto(
        List<AccessPathNode> nodes,
        boolean accessGranted,
        String finalReason
) {}