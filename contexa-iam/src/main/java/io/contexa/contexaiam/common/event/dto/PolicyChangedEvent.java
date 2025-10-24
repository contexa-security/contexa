package io.contexa.contexaiam.common.event.dto;

import java.util.Set;

public class PolicyChangedEvent extends DomainEvent {
    private final Long policyId;
    private final Set<Long> permissionIds; // [신규] 정책에 포함된 권한 ID 목록

    public PolicyChangedEvent(Long policyId, Set<Long> permissionIds) { // [수정] 생성자 변경
        this.policyId = policyId;
        this.permissionIds = permissionIds;
    }

    public Long getPolicyId() { return policyId; }
    public Set<Long> getPermissionIds() { return permissionIds; } // [신규] Getter 추가
}
