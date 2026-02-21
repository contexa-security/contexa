package io.contexa.contexaidentity.security.core.adapter.state.session;

import io.contexa.contexaidentity.security.core.adapter.StateAdapter;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.util.Objects;

public class SessionStateAdapter implements StateAdapter {

    @Override
    public String getId() {
        return "session";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext platformCtx) throws Exception {

        ApplicationContext appContext = Objects.requireNonNull(platformCtx.applicationContext(), "ApplicationContext from PlatformContext cannot be null");
        LogoutHandler logoutHandler = appContext.getBean("compositeLogoutHandler", LogoutHandler.class);

        http.logout(logout -> logout
                .addLogoutHandler(logoutHandler)
                .invalidateHttpSession(true)
                .clearAuthentication(true)
        );

        SessionStateConfigurer configurer = new SessionStateConfigurer(appContext);
        http.with(configurer, Customizer.withDefaults());
    }
}
