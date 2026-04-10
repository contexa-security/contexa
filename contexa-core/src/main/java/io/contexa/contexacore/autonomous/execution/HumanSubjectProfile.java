package io.contexa.contexacore.autonomous.execution;

import java.util.List;

public record HumanSubjectProfile(
        String userId,
        String organizationId,
        String tenantId,
        String department,
        String position,
        List<String> roleSet,
        List<String> authoritySet) {

    public HumanSubjectProfile {
        roleSet = roleSet == null ? List.of() : List.copyOf(roleSet);
        authoritySet = authoritySet == null ? List.of() : List.copyOf(authoritySet);
    }
}