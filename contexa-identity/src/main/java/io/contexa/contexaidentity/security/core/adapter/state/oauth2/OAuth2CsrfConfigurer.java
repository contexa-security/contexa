package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;

@Slf4j
public final class OAuth2CsrfConfigurer extends AbstractHttpConfigurer<OAuth2CsrfConfigurer, HttpSecurity> {

    private final boolean oauth2Csrf;

    public OAuth2CsrfConfigurer(boolean oauth2Csrf) {
        this.oauth2Csrf = oauth2Csrf;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        if (!oauth2Csrf) {
            http.csrf(AbstractHttpConfigurer::disable);
        }
        log.error("OAuth2CsrfConfigurer: CSRF {}", oauth2Csrf ? "enabled" : "disabled for OAuth2 mode");
    }
}
