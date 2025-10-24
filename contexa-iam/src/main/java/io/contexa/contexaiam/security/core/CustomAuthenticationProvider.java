package io.contexa.contexaiam.security.core;

import io.contexa.contexaiam.domain.dto.UserDto;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final AIReactiveUserDetailsService aiReactiveUserDetailsService;
//    private final PasswordEncoder passwordEncoder;
    private final ModelMapper modelMapper;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();
        CustomUserDetails userDetails = (CustomUserDetails) aiReactiveUserDetailsService.loadUserByUsername(loginId);

//        if(!passwordEncoder.matches(password, userDetails.getPassword())){
//            throw new BadCredentialsException("Invalid password");
//        }
        UserDto userDto = modelMapper.map(userDetails.getAccount(), UserDto.class);
        return new UsernamePasswordAuthenticationToken(userDto, userDetails.getPassword(), userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }
}
