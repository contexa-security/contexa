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

    @Override
    public void apply(HttpSecurity http, PlatformContext platformCtx) throws Exception {
        apply(http, platformCtx, null);
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext platformCtx, AuthenticationFlowConfig flowConfig) throws Exception {

        ApplicationContext appContext = Objects.requireNonNull(platformCtx.applicationContext(), "ApplicationContext from PlatformContext cannot be null");
        LogoutHandler logoutHandler = appContext.getBean("compositeLogoutHandler", LogoutHandler.class);

        String urlPrefix = flowConfig != null ? flowConfig.getUrlPrefix() : null;
        String logoutUrl = urlPrefix != null ? urlPrefix + "/logout" : "/logout";

        String logoutSuccessUrl;
        if (urlPrefix != null && MfaFlowTypeUtils.isMfaFlow(flowConfig.getTypeName())) {
            AuthContextProperties authProps = appContext.getBean(AuthContextProperties.class);
            String primaryLoginPage = authProps.getUrls().getPrimary().getFormLoginPage();
            logoutSuccessUrl = urlPrefix + primaryLoginPage;
        } else {
            logoutSuccessUrl = "/contexa/admin/login";
        }

        http.logout(logout -> logout
                .logoutUrl(logoutUrl)
                .logoutSuccessUrl(logoutSuccessUrl)
                .addLogoutHandler(logoutHandler)
                .invalidateHttpSession(true)
                .clearAuthentication(true)
        );

        SessionStateConfigurer configurer = new SessionStateConfigurer(appContext);
        http.with(configurer, Customizer.withDefaults());
    }
}
