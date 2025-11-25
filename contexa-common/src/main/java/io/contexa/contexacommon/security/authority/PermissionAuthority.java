package io.contexa.contexacommon.security.authority;

import io.contexa.contexacommon.entity.Permission;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Objects;

/**
 * Spring Security의 GrantedAuthority 인터페이스를 구현하여
 * 시스템적으로 'Permission' 타입을 나타내는 권한 객체입니다.
 * 내부적으로 Permission 엔티티를 래핑하여 Permission의 상세 정보에 접근할 수 있습니다.
 */
public class PermissionAuthority implements GrantedAuthority, Serializable {
    private static final long serialVersionUID = 1L;

    private final String authority;
    private final Long permissionId; // Permission 엔티티의 ID
    private final String permissionName; // Permission 엔티티의 이름 (예: DOCUMENT_READ)
    private final String targetType; // 대상 타입 (예: Document)
    private final String actionType; // 행동 타입 (예: READ)

    public PermissionAuthority(Permission permission) {
        Assert.notNull(permission, "Permission cannot be null");
        Assert.notNull(permission.getId(), "Permission ID cannot be null");
        Assert.hasText(permission.getName(), "Permission name cannot be empty");

        this.authority = permission.getName().toUpperCase(); // 권한명 자체를 Authority로 사용 (예: DOCUMENT_READ)
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
        if (o == null || getClass() != o.getClass()) return false; // 클래스 타입 비교
        PermissionAuthority that = (PermissionAuthority) o;
        return Objects.equals(permissionId, that.permissionId) && Objects.equals(permissionName, that.permissionName);
        // 또는 Objects.equals(authority, that.authority); authority는 permissionName 기반이므로.
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
