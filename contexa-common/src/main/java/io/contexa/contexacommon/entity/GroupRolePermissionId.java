package io.contexa.contexacommon.entity;

import java.io.Serializable;
import java.util.Objects;

public class GroupRolePermissionId implements Serializable {
    private Long group;
    private Long role;
    private Long permission;

    public GroupRolePermissionId() {}

    public GroupRolePermissionId(Long group, Long role, Long permission) {
        this.group = group;
        this.role = role;
        this.permission = permission;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GroupRolePermissionId that = (GroupRolePermissionId) o;
        return Objects.equals(group, that.group) && Objects.equals(role, that.role) && Objects.equals(permission, that.permission);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group, role, permission);
    }
}
