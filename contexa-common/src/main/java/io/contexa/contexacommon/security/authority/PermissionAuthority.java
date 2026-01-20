package io.contexa.contexacommon.security.authority;

import io.contexa.contexacommon.entity.Permission;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Objects;


public class PermissionAuthority implements GrantedAuthority, Serializable {
    private static final long serialVersionUID = 1L;

    private final String authority;
    private final Long permissionId; 
    private final String permissionName; 
    private final String targetType; 
    private final String actionType; 

    public PermissionAuthority(Permission permission) {
        Assert.notNull(permission, "Permission cannot be null");
        Assert.notNull(permission.getId(), "Permission ID cannot be null");
        Assert.hasText(permission.getName(), "Permission name cannot be empty");

        this.authority = permission.getName().toUpperCase(); 
        this.permissionId = permission.getId();
        this.permissionName = permission.getName();
        this.targetType = permission.getTargetType();
        this.actionType = permission.getActionType();
    }

    @Override
    public String getAuthority() {
        return authority;
    }

    public Long getPermissionId() {
        return permissionId;
    }

    public String getPermissionName() {
        return permissionName;
    }

    public String getTargetType() {
        return targetType;
    }

    public String getActionType() {
        return actionType;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false; 
        PermissionAuthority that = (PermissionAuthority) o;
        return Objects.equals(permissionId, that.permissionId) && Objects.equals(permissionName, that.permissionName);
        
    }

    @Override
    public int hashCode() {
        return Objects.hash(permissionId, permissionName);
    }

    @Override
    public String toString() {
        return "PermissionAuthority{" +
                "authority='" + authority + '\'' +
                ", permissionId=" + permissionId +
                '}';
    }
}
