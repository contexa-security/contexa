/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
        return !user.isExternalAuthOnly() && !user.isCredentialsExpired();
    }

    @Override
    public boolean isEnabled() {
        return !user.isExternalAuthOnly() && user.isEnabled();
    }
}
