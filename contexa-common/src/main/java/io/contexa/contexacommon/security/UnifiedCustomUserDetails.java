package io.contexa.contexacommon.security;

import io.contexa.contexacommon.dto.UserDto;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * 통합 CustomUserDetails
 *
 * Redis 직렬화 안전을 위해 UserDto 사용
 * Identity와 IAM의 CustomUserDetails를 통합
 *
 * 특징:
 * - UserDto 보유 (JPA 엔티티가 아님, Redis 직렬화 안전)
 * - RoleAuthority + PermissionAuthority 권한 모델
 * - AI Trust Tier 메타데이터 지원
 * - 불변성 보장 (originalAuthorities)
 */
@Getter
public class UnifiedCustomUserDetails implements UserDetails {

    private final UserDto user;
    private final Set<GrantedAuthority> originalAuthorities;  // 불변 보장

    /**
     * UserDto와 권한을 받아 생성
     *
     * @param user UserDto (Redis 직렬화 안전)
     * @param authorities RoleAuthority + PermissionAuthority 집합
     */
    public UnifiedCustomUserDetails(UserDto user, Set<GrantedAuthority> authorities) {
        this.user = user;
        this.originalAuthorities = Collections.unmodifiableSet(new HashSet<>(authorities));
        // UserDto에도 권한 설정 (Trust Tier 조정 전 원본)
        this.user.setAuthorities(this.originalAuthorities);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Trust Tier 조정된 권한이 UserDto에 있으면 그것을 반환
        // 없으면 originalAuthorities 반환
        Collection<? extends GrantedAuthority> adjustedAuthorities = user.getAuthorities();
        return adjustedAuthorities != null ? adjustedAuthorities : originalAuthorities;
    }

    public UserDto getAccount() {
        return user;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
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
