package io.contexa.contexaiam.security.core.auth;

import io.contexa.contexacommon.entity.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Objects;

/**
 * Spring Security의 GrantedAuthority 인터페이스를 구현하여
 * 시스템적으로 'Role' 타입을 나타내는 권한 객체입니다.
 * 내부적으로 Role 엔티티를 래핑하여 Role의 상세 정보에 접근할 수 있습니다.
 */
public class RoleAuthority implements GrantedAuthority, Serializable {
    private static final long serialVersionUID = 1L;
    private static final String ROLE_PREFIX = "ROLE_";

    private final String authority;
    private final Long roleId; // Role 엔티티의 ID
    private final String roleName; // Role 엔티티의 이름

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
        if (o == null || getClass() != o.getClass()) return false; // 클래스 타입 비교
        RoleAuthority that = (RoleAuthority) o;
        return Objects.equals(roleId, that.roleId) && Objects.equals(roleName, that.roleName);
        // 또는 Objects.equals(authority, that.authority); authority는 roleName 기반이므로.
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
