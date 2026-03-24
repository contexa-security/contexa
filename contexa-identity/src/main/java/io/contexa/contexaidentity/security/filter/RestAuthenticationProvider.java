package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
public class RestAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    @Nullable
    private final LoginPolicyHandler loginPolicyHandler;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();

        // Auto-unlock if lock duration has expired
        if (loginPolicyHandler != null) {
            loginPolicyHandler.checkAndUnlockIfExpired(loginId);
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(loginId);

        // Check account status before password verification
        if (!userDetails.isEnabled()) {
            throw new DisabledException("Account is disabled");
        }

        if (!userDetails.isAccountNonLocked()) {
            throw new LockedException("Account is locked");
        }

        // Verify password
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        // Check credentials expiry after successful password verification
        if (loginPolicyHandler != null && loginPolicyHandler.isCredentialsExpired(loginId)) {
            throw new CredentialsExpiredException("Password has expired");
        }

        UnifiedCustomUserDetails customUserDetails = (UnifiedCustomUserDetails) userDetails;
        return RestAuthenticationToken.authenticated(customUserDetails, customUserDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return RestAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
