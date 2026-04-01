package io.contexa.contexaiam.security.xacml.pap.dto;

public record PolicyConflictDto(
        Long newPolicyId,
        String newPolicyName,
        Long existingPolicyId,
        String existingPolicyName,
        String conflictDescription,
        Severity severity) {

    public enum Severity {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW
    }

    public PolicyConflictDto(Long newPolicyId, String newPolicyName,
                             Long existingPolicyId, String existingPolicyName,
                             String conflictDescription) {
        this(newPolicyId, newPolicyName, existingPolicyId, existingPolicyName,
                conflictDescription, Severity.HIGH);
    }
}
