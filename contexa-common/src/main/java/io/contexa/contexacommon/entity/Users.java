package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Entity
@Table(name = "users")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 100, unique = true, nullable = false)
    private String username;

    @Column(length = 255, unique = true)
    private String email;

    @Column(length = 255, nullable = false)
    private String password;

    @Column(length = 100, nullable = false)
    private String name;

    @Column(length = 20)
    private String phone;

    @Column(length = 100)
    private String department;

    @Column(length = 100)
    private String position;

    @Column(length = 500)
    private String profileImageUrl;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(nullable = false)
    @Builder.Default
    private boolean accountLocked = false;

    @Column(nullable = false)
    @Builder.Default
    private boolean credentialsExpired = false;

    @Column(nullable = false)
    @Builder.Default
    private int failedLoginAttempts = 0;

    @Column
    private LocalDateTime lockExpiresAt;

    @Column(nullable = false)
    @Builder.Default
    private boolean mfaEnabled = false;

    @Column(length = 50)
    private String preferredMfaFactor;

    @Column(length = 50)
    private String lastUsedMfaFactor;

    @Column
    private LocalDateTime lastMfaUsedAt;

    @Column
    private LocalDateTime lastLoginAt;

    @Column(length = 45)
    private String lastLoginIp;

    @Column
    private LocalDateTime passwordChangedAt;

    @Column(length = 10)
    @Builder.Default
    private String locale = "ko";

    @Column(length = 50)
    @Builder.Default
    private String timezone = "Asia/Seoul";

    @Column(nullable = false)
    @Builder.Default
    private boolean bridgeManaged = false;

    @Column(nullable = false)
    @Builder.Default
    private boolean externalAuthOnly = false;

    @Column(length = 255)
    private String externalSubjectId;

    @Column(length = 100)
    private String authenticationSource;

    @Column(length = 50)
    private String principalType;

    @Column(length = 255)
    private String organizationId;

    @Column(length = 120, unique = true)
    private String bridgeSubjectKey;

    @Column
    private LocalDateTime lastBridgedAt;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column
    private LocalDateTime updatedAt;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    @ToString.Exclude
    private Set<UserGroup> userGroups = new HashSet<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    @ToString.Exclude
    private Set<UserRole> userRoles = new HashSet<>();

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public String getPreferredMfaFactor() {
        if (preferredMfaFactor != null && !preferredMfaFactor.isEmpty()) {
            return preferredMfaFactor;
        }
        return lastUsedMfaFactor;
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

