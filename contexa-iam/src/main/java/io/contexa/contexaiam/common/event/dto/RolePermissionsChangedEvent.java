package io.contexa.contexaiam.common.event.dto;

import lombok.Getter;

/**
 * 역할(Role)에 할당된 권한(Permission)이 변경되었음을 알리는 도메인 이벤트.
 */
@Getter
public class RolePermissionsChangedEvent extends DomainEvent {
    private final Long roleId;

    public RolePermissionsChangedEvent(Long roleId) {
        this.roleId = roleId;
    }
}
