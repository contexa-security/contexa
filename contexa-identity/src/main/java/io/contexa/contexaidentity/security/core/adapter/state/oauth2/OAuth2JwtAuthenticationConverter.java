package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import io.contexa.contexacommon.repository.UserRepository;
import io.restassured.internal.common.assertion.Assertion;
import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class OAuth2JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final UserDetailsService userDetailsService;
    private final JwtGrantedAuthoritiesConverter scopeConverter = new JwtGrantedAuthoritiesConverter();
    private final Converter<Jwt, Collection<GrantedAuthority>> rolesConverter = new RolesClaimConverter();

    public OAuth2JwtAuthenticationConverter(HttpSecurity httpSecurity) {
        ApplicationContext applicationContext = httpSecurity.getSharedObject(ApplicationContext.class);
        this.userDetailsService = applicationContext.getBean(UserDetailsService.class);
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Assert.notNull(jwt.getSubject(), "Subject cannot be null");
        UserDetails userDetails = userDetailsService.loadUserByUsername(jwt.getSubject());
        Collection<? extends GrantedAuthority> userDetailsAuthorities = userDetails.getAuthorities();
        Collection<GrantedAuthority> scopeAuthorities = scopeConverter.convert(jwt);
        Collection<GrantedAuthority> roleAuthorities = rolesConverter.convert(jwt);

        Collection<GrantedAuthority> authorities = Stream.concat(scopeAuthorities.stream(),
                roleAuthorities != null ? roleAuthorities.stream() : Stream.empty()
        ).collect(Collectors.toSet());

        authorities.addAll(userDetailsAuthorities);

        return new JwtAuthenticationToken(jwt, authorities);
    }

    private static class RolesClaimConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {

            Collection<String> roles = jwt.getClaimAsStringList("roles");
            if (roles != null && !roles.isEmpty()) {
                return roles.stream()
                        .map(role -> new SimpleGrantedAuthority(
                                role.startsWith("ROLE_") ? role : "ROLE_" + role))
                        .collect(Collectors.toSet());
            }

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
