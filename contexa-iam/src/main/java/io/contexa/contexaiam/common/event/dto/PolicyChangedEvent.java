package io.contexa.contexaiam.common.event.dto;

import java.util.Set;

public class PolicyChangedEvent extends DomainEvent {
    private final Long policyId;
    private final Set<Long> permissionIds; 

    public PolicyChangedEvent(Long policyId, Set<Long> permissionIds) { 
        this.policyId = policyId;
        this.permissionIds = permissionIds;
    }

    public Long getPolicyId() { return policyId; }
    public Set<Long> getPermissionIds() { return permissionIds; } 
}
