package io.contexa.contexacore.autonomous.context;

import java.util.List;

public record ResourceContextDescriptor(
        String resourceId,
        String resourceType,
        String businessLabel,
        String sensitivity,
        List<String> allowedRoleFamilies,
        List<String> allowedActionFamilies,
        boolean privileged,
        boolean exportSensitive) {
}
