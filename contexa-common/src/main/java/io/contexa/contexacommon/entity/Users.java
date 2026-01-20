package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username; 

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String name;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true) 
    @Builder.Default
    @ToString.Exclude
    private Set<UserGroup> userGroups = new HashSet<>(); 

    @Column(nullable = false)
    private boolean mfaEnabled;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private LocalDateTime createdAt;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private LocalDateTime updatedAt;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private LocalDateTime lastMfaUsedAt;

    @Column
    private String preferredMfaFactor;

    @Column
    private String lastUsedMfaFactor;

    public String getPreferredMfaFactor() {
        if (preferredMfaFactor != null && !preferredMfaFactor.isEmpty()) {
            return preferredMfaFactor;
        }
        return lastUsedMfaFactor;
    }

    public void setPreferredMfaFactor(String factor) {
        this.preferredMfaFactor = factor;
    }


    @Transient
    public List<String> getRoleNames() {
        if (userGroups == null || userGroups.isEmpty()) {
            return Collections.emptyList();
        }
        return this.userGroups.stream()
                .map(UserGroup::getGroup)
                .filter(Objects::nonNull)
                .flatMap(group -> group.getGroupRoles().stream())
                .map(GroupRole::getRole)
                .filter(Objects::nonNull)
                .map(Role::getRoleName)
                .distinct()
                .sorted()
                .collect(Collectors.toList());
    }
    
    @Transient
    public List<String> getPermissionNames() {
        if (userGroups == null || userGroups.isEmpty()) {
            return Collections.emptyList();
        }
        return this.userGroups.stream()
                .map(UserGroup::getGroup)
                .filter(Objects::nonNull)
                .flatMap(group -> group.getGroupRoles().stream())
                .map(GroupRole::getRole)
                .filter(Objects::nonNull)
                .flatMap(role -> role.getRolePermissions().stream())
                .map(RolePermission::getPermission)
                .filter(Objects::nonNull)
                .map(Permission::getName)
                .distinct()
                .sorted()
                .collect(Collectors.toList());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        
        if (!(o instanceof Users users)) return false;
        
        return id != null && Objects.equals(id, users.id);
    }

    @Override
    public int hashCode() {
        
        
        return getClass().hashCode();
    }
}