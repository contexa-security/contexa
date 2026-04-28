package io.contexa.contexacommon.security;

import io.contexa.contexacommon.domain.UserDto;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Getter
public class UnifiedCustomUserDetails implements UserDetails {

    private final UserDto user;
    private final Set<GrantedAuthority> originalAuthorities;  

    public UnifiedCustomUserDetails(UserDto user, Set<GrantedAuthority> authorities) {
        this.user = user;
        this.originalAuthorities = Collections.unmodifiableSet(new HashSet<>(authorities));
        this.user.setAuthorities(this.originalAuthorities);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
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
        // Account expiry is a separate concept from credential (password) expiry.
        // No dedicated field exists today, so the account itself never expires;
        // password expiry is reported via isCredentialsNonExpired() below.
        return true;
    }

    /**
     * Returns whether the account is not locked.
     * Auto-unlock semantics: when the lock has a {@code lockExpiresAt} in the past,
     * the account is treated as unlocked at the authentication boundary so that
     * Spring Security's standard pre-authentication check (DaoAuthenticationProvider
     * -> AccountStatusUserDetailsChecker) does not throw a stale LockedException.
     * The actual DB flip is performed by the success/failure handlers
     * (LoginPolicyService.checkAndUnlockIfExpired / onLoginSuccess).
     */
    @Override
    public boolean isAccountNonLocked() {
        if (!user.isAccountLocked()) {
            return true;
        }
        LocalDateTime expiresAt = user.getLockExpiresAt();
        return expiresAt != null && LocalDateTime.now().isAfter(expiresAt);
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !user.isCredentialsExpired();
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }
}
