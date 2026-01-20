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
    @GeneratedValue(strategy = GenerationType.IDENTITY) 
    @Column(name = "role_id")
    private Long id;

    @Column(name = "role_name", unique = true, nullable = false) 
    private String roleName;

    @Column(name = "role_desc")
    private String roleDesc;

    @Column(name = "is_expression")
    private String isExpression;

    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL, orphanRemoval = true) 
    @Builder.Default
    @ToString.Exclude
    private Set<GroupRole> groupRoles = new HashSet<>(); 

    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL, orphanRemoval = true) 
    @Builder.Default
    @ToString.Exclude
    private Set<RolePermission> rolePermissions = new HashSet<>(); 
}
