package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OAuth2JwtAuthenticationConverterTest {

    @Mock
    private HttpSecurity httpSecurity;
    @Mock
    private ApplicationContext applicationContext;
    @Mock
    private UserDetailsService userDetailsService;
    @Mock
    private UserDetails userDetails;

    private OAuth2JwtAuthenticationConverter converter;

    @BeforeEach
    void setUp() {
        when(httpSecurity.getSharedObject(ApplicationContext.class)).thenReturn(applicationContext);
        when(applicationContext.getBean(UserDetailsService.class)).thenReturn(userDetailsService);

        converter = new OAuth2JwtAuthenticationConverter(httpSecurity);
    }

    @Test
    void convert_shouldExtractAuthoritiesFromRolesClaim() {
        Jwt jwt = buildJwt("user1", "roles", List.of("ADMIN", "USER"));
        stubUserDetails("user1", List.of());

        AbstractAuthenticationToken token = converter.convert(jwt);

        assertThat(token).isNotNull();
        Collection<String> authorityStrings = extractAuthorityStrings(token);
        assertThat(authorityStrings).contains("ROLE_ADMIN", "ROLE_USER");
    }

    @Test
    void convert_shouldAddRolePrefixWhenMissing() {
        Jwt jwt = buildJwt("user1", "roles", List.of("MANAGER"));
        stubUserDetails("user1", List.of());

        AbstractAuthenticationToken token = converter.convert(jwt);

        Collection<String> authorityStrings = extractAuthorityStrings(token);
        assertThat(authorityStrings).contains("ROLE_MANAGER");
    }

    @Test
    void convert_shouldNotDuplicateRolePrefix() {
        Jwt jwt = buildJwt("user1", "roles", List.of("ROLE_ADMIN"));
        stubUserDetails("user1", List.of());

        AbstractAuthenticationToken token = converter.convert(jwt);

        Collection<String> authorityStrings = extractAuthorityStrings(token);
        assertThat(authorityStrings).contains("ROLE_ADMIN");
        // Should not contain ROLE_ROLE_ADMIN
        assertThat(authorityStrings).doesNotContain("ROLE_ROLE_ADMIN");
    }

    @Test
    void convert_shouldExtractFromAuthoritiesClaim_whenNoRoles() {
        Jwt jwt = buildJwt("user1", "authorities", List.of("READ_PRIVILEGE", "WRITE_PRIVILEGE"));
        stubUserDetails("user1", List.of());

        AbstractAuthenticationToken token = converter.convert(jwt);

        Collection<String> authorityStrings = extractAuthorityStrings(token);
        assertThat(authorityStrings).contains("READ_PRIVILEGE", "WRITE_PRIVILEGE");
    }

    @Test
    void convert_shouldMergeUserDetailsAuthorities() {
        Jwt jwt = buildJwt("user1", "roles", List.of("ADMIN"));
        stubUserDetails("user1", List.of(new SimpleGrantedAuthority("SCOPE_read")));

        AbstractAuthenticationToken token = converter.convert(jwt);

        Collection<String> authorityStrings = extractAuthorityStrings(token);
        assertThat(authorityStrings).contains("ROLE_ADMIN", "SCOPE_read");
    }

    @Test
    void convert_shouldThrowOnNullSubject() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claim("roles", List.of("ADMIN"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();

        assertThatThrownBy(() -> converter.convert(jwt))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // -- helper methods --

    private Jwt buildJwt(String subject, String claimName, List<String> claimValues) {
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject(subject)
                .claim(claimName, claimValues)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
    }

    @SuppressWarnings("unchecked")
    private void stubUserDetails(String username, List<? extends GrantedAuthority> authorities) {
        when(userDetailsService.loadUserByUsername(username)).thenReturn(userDetails);
        when(userDetails.getAuthorities()).thenReturn((Collection) authorities);
    }

    private Collection<String> extractAuthorityStrings(AbstractAuthenticationToken token) {
        return token.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }
}
