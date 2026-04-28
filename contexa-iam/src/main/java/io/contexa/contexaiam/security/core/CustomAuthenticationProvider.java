package io.contexa.contexaiam.security.core;

import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final LoginPolicyHandler loginPolicyService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();

        UserDetails userDetails = userDetailsService.loadUserByUsername(loginId);

        // Pre-authentication checks: replicate DaoAuthenticationProvider's AccountStatusUserDetailsChecker
        // because this provider implements AuthenticationProvider directly. Without these explicit checks,
        // a locked / disabled account would still authenticate when the password matches.
        if (!userDetails.isEnabled()) {
            throw new DisabledException("Account is disabled");
        }
        if (!userDetails.isAccountNonLocked()) {
            throw new LockedException("Account is locked");
        }
        if (!userDetails.isAccountNonExpired()) {
            throw new AccountExpiredException("Account has expired");
        }

        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        // Post-authentication credential check (kept after password match to preserve previous behavior).
        if (!userDetails.isCredentialsNonExpired() || loginPolicyService.isCredentialsExpired(loginId)) {
            throw new CredentialsExpiredException("Password has expired");
        }

        UnifiedCustomUserDetails customUserDetails = (UnifiedCustomUserDetails) userDetails;
        if (customUserDetails.getAccount().isExternalAuthOnly()) {
            throw new BadCredentialsException("External authentication only account");
        }
        return UsernamePasswordAuthenticationToken.authenticated(customUserDetails, null, customUserDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
