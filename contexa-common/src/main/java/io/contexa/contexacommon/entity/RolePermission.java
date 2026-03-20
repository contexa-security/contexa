package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Objects;

@Entity
@Table(name = "role_permissions")
@IdClass(RolePermissionId.class)
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
    private Role role;

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "permission_id")
    @ToString.Exclude
    private Permission permission;

    @Column(nullable = false, updatable = false)
    private LocalDateTime assignedAt;

    @Column(length = 100)
    private String assignedBy;

    @PrePersist
    protected void onCreate() {
        assignedAt = LocalDateTime.now();
    }

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


@NoArgsConstructor
@AllArgsConstructor
class RolePermissionId implements Serializable {
    private Long role;
    private Long permission;

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
