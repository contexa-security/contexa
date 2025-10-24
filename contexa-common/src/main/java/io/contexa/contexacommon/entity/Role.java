package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "ROLE")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Role implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // IDENTITY 전략으로 통일하는 것이 좋음
    @Column(name = "role_id")
    private Long id;

    @Column(name = "role_name", unique = true, nullable = false) // role_name도 UNIQUE로 설정하는 것이 좋음
    private String roleName;

    @Column(name = "role_desc")
    private String roleDesc;

    @Column(name = "is_expression")
    private String isExpression;

    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL, orphanRemoval = true) // GroupRole 엔티티의 'role' 필드에 매핑
    @Builder.Default
    @ToString.Exclude
    private Set<GroupRole> groupRoles = new HashSet<>(); // 이 역할을 가진 그룹들

    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL, orphanRemoval = true) // RolePermission 엔티티의 'role' 필드에 매핑
    @Builder.Default
    @ToString.Exclude
    private Set<RolePermission> rolePermissions = new HashSet<>(); // 이 역할에 할당된 권한들
}
