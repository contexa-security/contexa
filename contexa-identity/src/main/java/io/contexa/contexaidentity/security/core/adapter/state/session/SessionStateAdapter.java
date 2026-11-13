/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.core.adapter.state.session;

import io.contexa.contexaidentity.security.core.adapter.StateAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexacommon.properties.AuthContextProperties;
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

    /** Says that the address after a sign-out was given to the chain before the application's settings. */
    private enum LogoutDefaults { APPLIED }

    @Override
    public void apply(HttpSecurity http, PlatformContext platformCtx) throws Exception {
        apply(http, platformCtx, null);
    }

    /**
     * The address the browser is sent to after a sign-out, given before the application's settings: a
     * {@code logoutSuccessUrl(...)} or a {@code logoutSuccessHandler(...)} of the global customizer or of the flow's
     * {@code logout(...)} option stays. Written with the state, after them, it took their place.
     */
    @Override
    public void applyDefaults(HttpSecurity http, PlatformContext platformCtx, AuthenticationFlowConfig flowConfig) throws Exception {
        ApplicationContext appContext = Objects.requireNonNull(platformCtx.applicationContext(), "ApplicationContext from PlatformContext cannot be null");
        String logoutSuccessUrl = logoutSuccessUrl(appContext, flowConfig);
        http.logout(logout -> logout.logoutSuccessUrl(logoutSuccessUrl));
        http.setSharedObject(LogoutDefaults.class, LogoutDefaults.APPLIED);
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext platformCtx, AuthenticationFlowConfig flowConfig) throws Exception {

        ApplicationContext appContext = Objects.requireNonNull(platformCtx.applicationContext(), "ApplicationContext from PlatformContext cannot be null");
        LogoutHandler logoutHandler = appContext.getBean("contexaCompositeLogoutHandler", LogoutHandler.class);

        String urlPrefix = flowConfig != null ? flowConfig.getUrlPrefix() : null;
        String logoutUrl = urlPrefix != null ? urlPrefix + "/logout" : "/logout";
        // A caller that applies the state alone, without its defaults first, gets the address after a sign-out here.
        boolean defaultsApplied = http.getSharedObject(LogoutDefaults.class) != null;
        String logoutSuccessUrl = defaultsApplied ? null : logoutSuccessUrl(appContext, flowConfig);

        // The address of the sign-out is the state's: the Zero Trust filters and the filter of an unfinished MFA let a
        // restricted session through to it, so it does not follow a logoutUrl(...) of the application.
        http.logout(logout -> {
            logout.logoutUrl(logoutUrl);
            if (logoutSuccessUrl != null) {
                logout.logoutSuccessUrl(logoutSuccessUrl);
            }
            logout.addLogoutHandler(logoutHandler)
                    .invalidateHttpSession(true)
                    .clearAuthentication(true);
        });

        SessionStateConfigurer configurer = new SessionStateConfigurer(appContext);
        // The customizer the flow's .session(customizer) gave.
        http.with(configurer, flowConfig != null
                ? flowConfig.stateCustomizer(SessionStateConfigurer.class)
                : Customizer.withDefaults());
    }

    private static String logoutSuccessUrl(ApplicationContext appContext, AuthenticationFlowConfig flowConfig) {
        String urlPrefix = flowConfig != null ? flowConfig.getUrlPrefix() : null;
        if (urlPrefix != null && MfaFlowTypeUtils.isMfaFlow(flowConfig.getTypeName())) {
            AuthContextProperties authProps = appContext.getBean(AuthContextProperties.class);
            return urlPrefix + authProps.getUrls().getPrimary().getFormLoginPage();
        }
        return "/contexa/admin/login";
    }
}
