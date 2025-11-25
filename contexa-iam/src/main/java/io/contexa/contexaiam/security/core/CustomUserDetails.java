package io.contexa.contexaiam.security.core;

import io.contexa.contexacommon.security.authority.PermissionAuthority;
import io.contexa.contexacommon.security.authority.RoleAuthority;
import io.contexa.contexacommon.entity.GroupRole;
import io.contexa.contexacommon.entity.RolePermission;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.Users;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

@Getter
public class CustomUserDetails implements UserDetails {

    private final Users users;
    private final Set<GrantedAuthority> authorities;
    
    // AI-Native Trust Tier 관련 필드 추가
    @Setter
    private Set<GrantedAuthority> adjustedAuthorities;
    @Setter
    private Double trustScore;
    @Setter
    private String trustTier;
    @Setter
    private Map<String, Object> trustMetadata;

    public CustomUserDetails(Users user) {
        this.users = user;
        this.authorities = initializeAuthorities(user); // 권한 초기화 로직 분리
    }

    private Set<GrantedAuthority> initializeAuthorities(Users user) {
        Set<GrantedAuthority> collectedAuthorities = new HashSet<>();

        Optional.ofNullable(user.getUserGroups()) // Users가 가진 userGroups (Set<UserGroup>)
                .orElse(Collections.emptySet()) // null이면 빈 Set 반환
                .stream()
                .map(UserGroup::getGroup) // UserGroup에서 Group 엔티티 추출
                .filter(Objects::nonNull) // null인 Group 필터링
                .flatMap(group -> Optional.ofNullable(group.getGroupRoles()).orElse(Collections.emptySet()).stream()) // Group이 가진 groupRoles (Set<GroupRole>)
                .map(GroupRole::getRole) // GroupRole에서 Role 엔티티 추출
                .filter(Objects::nonNull) // null인 Role 필터링
                .forEach(role -> {
                    // 1. RoleAuthority 추가
                    collectedAuthorities.add(new RoleAuthority(role));

                    // 2. Role에 연결된 Permissions 추가
                    Optional.ofNullable(role.getRolePermissions()) // Role이 가진 rolePermissions (Set<RolePermission>)
                            .orElse(Collections.emptySet()) // null이면 빈 Set 반환
                            .stream()
                            .map(RolePermission::getPermission) // RolePermission에서 Permission 엔티티 추출
                            .filter(Objects::nonNull) // null인 Permission 필터링
                            .forEach(permission -> {
                                collectedAuthorities.add(new PermissionAuthority(permission));
                            });
                });

        return Collections.unmodifiableSet(collectedAuthorities); // 불변 Set으로 반환
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Trust Tier로 조정된 권한이 있으면 그것을 반환, 없으면 원본 권한 반환
        return this.adjustedAuthorities != null ? this.adjustedAuthorities : this.authorities;
    }

    public Users getAccount() {
        return users;
    }

    @Override
    public String getPassword() {
        return users.getPassword();
    }

    @Override
    public String getUsername() {
        return users.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
