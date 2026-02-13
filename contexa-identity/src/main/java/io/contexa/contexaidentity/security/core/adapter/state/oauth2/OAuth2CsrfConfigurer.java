package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@Slf4j
public final class OAuth2CsrfConfigurer extends AbstractHttpConfigurer<OAuth2CsrfConfigurer, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        log.debug("OAuth2CsrfConfigurer: CSRF disabled.");
    }
}
