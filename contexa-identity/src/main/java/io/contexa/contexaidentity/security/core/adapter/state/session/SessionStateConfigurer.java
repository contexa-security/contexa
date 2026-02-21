package io.contexa.contexaidentity.security.core.adapter.state.session;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

public class SessionStateConfigurer extends AbstractHttpConfigurer<SessionStateConfigurer, HttpSecurity> {

    private final ApplicationContext appContext;

    public SessionStateConfigurer(ApplicationContext appContext) {
        this.appContext = appContext;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        http.sessionManagement(session -> session
                .sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::changeSessionId)
        );
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        LogoutHandler logoutHandler = appContext.getBean("compositeLogoutHandler", LogoutHandler.class);

        http.logout(logout -> logout
                .addLogoutHandler(logoutHandler)
                .invalidateHttpSession(true)
                .clearAuthentication(true)
        );
    }
}
