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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexaiam.admin.web.auth.filter.ActiveSessionEndListener;
import io.contexa.contexaiam.admin.web.auth.filter.SessionTrackingFilter;
import io.contexa.contexaiam.admin.web.auth.service.ActiveSessionCleanupScheduler;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Session tracking follows the sessions Contexa creates. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnOwnership(SecurityOwnershipMode.CONTEXA_OWNED)
public class IamAdminSessionContexaOwnedConfiguration {

    @Bean(name = "contexaSessionTrackingFilter")
    @ConditionalOnMissingBean(SessionTrackingFilter.class)
    public FilterRegistrationBean<SessionTrackingFilter> sessionTrackingFilter(
            SessionManagementService contexaSessionManagementService,
            ActiveSessionRepository activeSessionRepository) {
        FilterRegistrationBean<SessionTrackingFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new SessionTrackingFilter(contexaSessionManagementService, activeSessionRepository));
        registration.addUrlPatterns("/*");
        registration.setName("contexaSessionTrackingFilter");
        registration.setOrder(200);
        return registration;
    }

    /** K73: a tracked session whose HTTP session ends, or whose id is replaced, is no longer active. */
    @Bean(name = "contexaActiveSessionEndListener")
    @ConditionalOnMissingBean(name = "contexaActiveSessionEndListener")
    public ServletListenerRegistrationBean<ActiveSessionEndListener> activeSessionEndListener(
            SessionManagementService contexaSessionManagementService) {
        return new ServletListenerRegistrationBean<>(new ActiveSessionEndListener(contexaSessionManagementService));
    }

    /**
     * K73: the tracked sessions that ended without a word (their node stopped) go after the HTTP session's idle limit,
     * and the ended ones after their retention.
     */
    @Bean(name = "contexaActiveSessionCleanupScheduler")
    @ConditionalOnMissingBean
    public ActiveSessionCleanupScheduler activeSessionCleanupScheduler(
            SessionManagementService contexaSessionManagementService,
            ObjectProvider<ServerProperties> serverProperties) {
        ServerProperties server = serverProperties.getIfAvailable();
        return new ActiveSessionCleanupScheduler(contexaSessionManagementService,
                server != null ? server.getServlet().getSession().getTimeout() : null);
    }
}
