package io.contexa.contexaiam.security.core;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CustomAuthenticationProviderTest {

    @Test
    void shouldRejectPasswordAuthenticationForExternalAuthOnlyAccount() {
        UserDetailsService userDetailsService = mock(UserDetailsService.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        CustomAuthenticationProvider provider = new CustomAuthenticationProvider(userDetailsService, passwordEncoder);

        UserDto account = UserDto.builder()
                .id(100L)
                .username("brg_sync_user")
                .password("{noop}BRIDGE_EXTERNAL_ONLY::seed")
                .name("Bridge User")
                .enabled(true)
                .externalAuthOnly(true)
                .build();
        UnifiedCustomUserDetails userDetails = new UnifiedCustomUserDetails(account, Set.of());
        when(userDetailsService.loadUserByUsername("brg_sync_user")).thenReturn(userDetails);

        assertThatThrownBy(() -> provider.authenticate(new UsernamePasswordAuthenticationToken("brg_sync_user", "pw")))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("External authentication only account");
    }

    @Test
    void shouldAuthenticateLocalAccountWhenPasswordMatches() {
        UserDetailsService userDetailsService = mock(UserDetailsService.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        CustomAuthenticationProvider provider = new CustomAuthenticationProvider(userDetailsService, passwordEncoder);

        UserDto account = UserDto.builder()
                .id(101L)
                .username("local-user")
                .password("encoded")
                .name("Local User")
                .enabled(true)
                .externalAuthOnly(false)
                .build();
        UnifiedCustomUserDetails userDetails = new UnifiedCustomUserDetails(account, Set.of());
        when(userDetailsService.loadUserByUsername("local-user")).thenReturn(userDetails);
        when(passwordEncoder.matches("pw", "encoded")).thenReturn(true);

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("local-user", "pw");
        var result = provider.authenticate(authentication);

        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getName()).isEqualTo("local-user");
    }
}
