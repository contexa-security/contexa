package io.contexa.contexaidentity.security.core.adapter.state.session;

import io.contexa.contexaidentity.security.core.adapter.StateAdapter;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class SessionStateAdapter implements StateAdapter {

    @Override
    public String getId() {
        return "session";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {
        SessionStateConfigurer configurer = new SessionStateConfigurer();
        http.with(configurer, Customizer.withDefaults());
    }
}
