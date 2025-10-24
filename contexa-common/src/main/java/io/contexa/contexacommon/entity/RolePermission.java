package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "ROLE_PERMISSIONS") // Role과 Permission의 조인 테이블
@IdClass(RolePermissionId.class) // 복합 PK를 위한 @IdClass 사용
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RolePermission implements Serializable {
    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id")
    @ToString.Exclude
    private Role role; // 역할 엔티티

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "permission_id")
    @ToString.Exclude
    private Permission permission; // 권한 엔티티

    // 추가 속성 (예: 할당일, 유효기간, 할당자 등)
    // @Column(name = "assigned_at")
    // private Instant assignedAt;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RolePermission that = (RolePermission) o;
        return Objects.equals(role, that.role) &&
                Objects.equals(permission, that.permission);
    }

    @Override
    public int hashCode() {
        return Objects.hash(role, permission);
    }
}

// 복합 PK를 위한 ID 클래스
@NoArgsConstructor
@AllArgsConstructor
class RolePermissionId implements Serializable {
    private Long role;      // Role 엔티티의 ID 타입과 일치해야 함
    private Long permission; // Permission 엔티티의 ID 타입과 일치해야 함

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RolePermissionId that = (RolePermissionId) o;
        return Objects.equals(role, that.role) && Objects.equals(permission, that.permission);
    }

    @Override
    public int hashCode() {
        return Objects.hash(role, permission);
    }
}
