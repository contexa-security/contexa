package io.contexa.contexaiam.common.event.dto;

import lombok.Getter;


@Getter
public class RolePermissionsChangedEvent extends DomainEvent {
    private final Long roleId;

    public RolePermissionsChangedEvent(Long roleId) {
        this.roleId = roleId;
    }
}
