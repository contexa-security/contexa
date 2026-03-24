package io.contexa.contexacommon.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityContextJwtStampResolversTest {

    private final SecurityContextAuthenticationStampResolver authenticationStampResolver = new SecurityContextAuthenticationStampResolver();
    private final SecurityContextAuthorizationStampResolver authorizationStampResolver = new SecurityContextAuthorizationStampResolver();

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void resolversShouldAbsorbJwtClaimsFromSecurityContextWithoutCustomerCustomization() {
        Jwt jwt = Jwt.withTokenValue("header.payload.signature")
                .header("alg", "RS256")
                .claim("sub", "oauth-user-1")
                .claim("name", "OAuth User")
                .claim("organizationId", "tenant-oauth")
                .claim("department", "growth")
                .claim("roles", List.of("ADMIN"))
                .claim("permissions", List.of("REPORT_EXPORT"))
                .claim("scope", "profile reports.read")
                .claim("auth_time", 1711276200L)
                .claim("acr", "loa3")
                .claim("amr", List.of("pwd", "otp"))
                .build();
        JwtAuthenticationToken authentication = new JwtAuthenticationToken(
                jwt,
                List.of(new SimpleGrantedAuthority("SCOPE_profile"), new SimpleGrantedAuthority("SCOPE_reports.read"))
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        RequestContextSnapshot requestContext = new RequestContextSnapshot(
                "/api/profile",
                "GET",
                "127.0.0.1",
                "JUnit",
                null,
                "request-1",
                "/api/profile",
                null,
                false,
                Instant.now()
        );

        AuthenticationStamp authenticationStamp = authenticationStampResolver.resolve(null, requestContext, new BridgeProperties()).orElseThrow();
        AuthorizationStamp authorizationStamp = authorizationStampResolver.resolve(null, requestContext, new BridgeProperties()).orElseThrow();

        assertThat(authenticationStamp.principalId()).isEqualTo("oauth-user-1");
        assertThat(authenticationStamp.displayName()).isEqualTo("OAuth User");
        assertThat(authenticationStamp.authenticationType()).isEqualTo("JwtAuthenticationToken");
        assertThat(authenticationStamp.authenticationAssurance()).isEqualTo("loa3");
        assertThat(authenticationStamp.mfaCompleted()).isTrue();
        assertThat(authenticationStamp.authenticationTime()).isEqualTo(Instant.ofEpochSecond(1711276200L));
        assertThat(authenticationStamp.attributes()).containsEntry("organizationId", "tenant-oauth");
        assertThat(authenticationStamp.attributes()).containsEntry("department", "growth");

        assertThat(authorizationStamp.effect()).isEqualTo(AuthorizationEffect.UNKNOWN);
        assertThat(authorizationStamp.effectiveRoles()).contains("ROLE_ADMIN");
        assertThat(authorizationStamp.effectiveAuthorities()).contains("REPORT_EXPORT", "SCOPE_profile", "SCOPE_reports.read");
        assertThat(authorizationStamp.privileged()).isTrue();
    }
}
