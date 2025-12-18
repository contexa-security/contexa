package io.contexa.contexaiam.security.core;

import io.contexa.contexacommon.dto.UserDto;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
//    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();
        UserDetails userDetails = userDetailsService.loadUserByUsername(loginId);

//        if(!passwordEncoder.matches(password, userDetails.getPassword())){
//            throw new BadCredentialsException("Invalid password");
//        }

        // UnifiedCustomUserDetails로 캐스팅하여 UserDto 획득 (ModelMapper 제거)
        UnifiedCustomUserDetails customUserDetails = (UnifiedCustomUserDetails) userDetails;
        UserDto userDto = customUserDetails.getAccount();
        return UsernamePasswordAuthenticationToken.authenticated(customUserDetails, null, customUserDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }
}
