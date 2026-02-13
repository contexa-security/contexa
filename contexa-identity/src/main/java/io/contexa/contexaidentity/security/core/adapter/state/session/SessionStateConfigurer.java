package io.contexa.contexaidentity.security.core.adapter.state.session;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

public class SessionStateConfigurer extends AbstractHttpConfigurer<SessionStateConfigurer, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) throws Exception {
        http.sessionManagement(session -> session
                .sessionFixation(fix -> fix.changeSessionId())
        );
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        LogoutHandler logoutHandler = http.getSharedObject(LogoutHandler.class);
        LogoutSuccessHandler logoutSuccessHandler = http.getSharedObject(LogoutSuccessHandler.class);

        if (logoutHandler != null && logoutSuccessHandler != null) {
            http.logout(logout -> logout
                    .addLogoutHandler(logoutHandler)
                    .logoutSuccessHandler(logoutSuccessHandler)
                    .invalidateHttpSession(true)
                    .clearAuthentication(true)
            );
        }
    }
}
