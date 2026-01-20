package io.contexa.contexaiam.security.core.auth;

import io.contexa.contexacommon.entity.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Objects;


public class RoleAuthority implements GrantedAuthority, Serializable {
    private static final long serialVersionUID = 1L;
    private static final String ROLE_PREFIX = "ROLE_";

    private final String authority;
    private final Long roleId; 
    private final String roleName; 

    public RoleAuthority(Role role) {
        Assert.notNull(role, "Role cannot be null");
        Assert.notNull(role.getId(), "Role ID cannot be null");
        Assert.hasText(role.getRoleName(), "Role name cannot be empty");

        this.authority = role.getRoleName().startsWith("ROLE_") ? role.getRoleName() : ROLE_PREFIX + role.getRoleName().toUpperCase();
        this.roleId = role.getId();
        this.roleName = role.getRoleName();
    }

    @Override
    public String getAuthority() {
        return authority;
    }

    public Long getRoleId() {
        return roleId;
    }

    public String getRoleName() {
        return roleName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false; 
        RoleAuthority that = (RoleAuthority) o;
        return Objects.equals(roleId, that.roleId) && Objects.equals(roleName, that.roleName);
        
    }

    @Override
    public int hashCode() {
        return Objects.hash(roleId, roleName);
    }

    @Override
    public String toString() {
        return "RoleAuthority{" +
                "authority='" + authority + '\'' +
                ", roleId=" + roleId +
                '}';
    }
}
