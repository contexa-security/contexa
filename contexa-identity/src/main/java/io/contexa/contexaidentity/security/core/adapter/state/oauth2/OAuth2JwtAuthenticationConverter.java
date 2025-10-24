package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * OAuth2 JWT를 Spring Security Authentication 객체로 변환하는 Converter입니다.
 *
 * <p>JWT의 클레임에서 권한 정보를 추출하여 GrantedAuthority로 변환합니다.
 * - "scope" 클레임: OAuth2 표준 스코프
 * - "roles" 클레임: AIDC 프레임워크의 역할
 * - "authorities" 클레임: 명시적 권한
 */
public class OAuth2JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter scopeConverter = new JwtGrantedAuthoritiesConverter();
    private final Converter<Jwt, Collection<GrantedAuthority>> rolesConverter = new RolesClaimConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        // Scope 기반 권한 (OAuth2 표준)
        Collection<GrantedAuthority> scopeAuthorities = scopeConverter.convert(jwt);

        // Roles 기반 권한 (AIDC 프레임워크)
        Collection<GrantedAuthority> roleAuthorities = rolesConverter.convert(jwt);

        // 두 가지 권한을 병합
        Collection<GrantedAuthority> authorities = Stream.concat(
                scopeAuthorities != null ? scopeAuthorities.stream() : Stream.empty(),
                roleAuthorities != null ? roleAuthorities.stream() : Stream.empty()
        ).collect(Collectors.toSet());

        return new JwtAuthenticationToken(jwt, authorities);
    }

    /**
     * JWT의 "roles" 또는 "authorities" 클레임에서 권한을 추출하는 Converter
     */
    private static class RolesClaimConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            // "roles" 클레임 확인
            Collection<String> roles = jwt.getClaimAsStringList("roles");
            if (roles != null && !roles.isEmpty()) {
                return roles.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toSet());
            }

            // "authorities" 클레임 확인
            Collection<String> authorities = jwt.getClaimAsStringList("authorities");
            if (authorities != null && !authorities.isEmpty()) {
                return authorities.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toSet());
            }

            return null;
        }
    }
}
