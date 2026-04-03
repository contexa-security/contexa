package io.contexa.contexacommon.entity;

import java.io.Serializable;
import java.util.Objects;

public class UserRolePermissionId implements Serializable {
    private Long user;
    private Long role;
    private Long permission;

    public UserRolePermissionId() {}

    public UserRolePermissionId(Long user, Long role, Long permission) {
        this.user = user;
        this.role = role;
        this.permission = permission;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserRolePermissionId that = (UserRolePermissionId) o;
        return Objects.equals(user, that.user) && Objects.equals(role, that.role) && Objects.equals(permission, that.permission);
    }

    @Override
    public int hashCode() {
        return Objects.hash(user, role, permission);
    }
}
