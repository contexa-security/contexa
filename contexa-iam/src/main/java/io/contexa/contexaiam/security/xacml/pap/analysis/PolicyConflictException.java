package io.contexa.contexaiam.security.xacml.pap.analysis;

import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;

import java.util.List;

/**
 * Thrown when a policy creation or update would cause critical conflicts
 * with existing policies.
 */
public class PolicyConflictException extends RuntimeException {

    private final List<PolicyConflictDto> conflicts;

    public PolicyConflictException(String message, List<PolicyConflictDto> conflicts) {
        super(message);
        this.conflicts = conflicts;
    }

    public List<PolicyConflictDto> getConflicts() {
        return conflicts;
    }
}
