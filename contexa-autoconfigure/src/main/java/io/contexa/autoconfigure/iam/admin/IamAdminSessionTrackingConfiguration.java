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

import io.contexa.autoconfigure.ai.ContexaSlotFilterRegistration;
import io.contexa.autoconfigure.ai.ContexaServletFilterOrder;
import io.contexa.contexaiam.admin.web.auth.filter.ActiveSessionEndListener;
import io.contexa.contexaiam.admin.web.auth.filter.SessionTrackingFilter;
import io.contexa.contexaiam.admin.web.auth.filter.TrackedSessionMarks;
import io.contexa.contexaiam.admin.web.auth.service.ActiveSessionCleanupScheduler;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Session tracking follows the sessions of whoever is signed in, in every way of running Contexa (R-8 of
 * docs/agent/운영모드-정상화-구현계획.md): it observes a session's id only, keeps what it needs on Contexa's side
 * ({@link TrackedSessionMarks}) and writes nothing into the application's session.
 */
@Configuration(proxyBeanMethods = false)
public class IamAdminSessionTrackingConfiguration {

    /** When each session was last checked and tracked, shared by the tracking filter and the listener of the sessions' ends. */
    @Bean(name = "contexaTrackedSessionMarks")
    @ConditionalOnMissingBean(name = "contexaTrackedSessionMarks")
    public TrackedSessionMarks trackedSessionMarks() {
        return new TrackedSessionMarks();
    }

    /** The last member of Contexa's filter slot (R-10 of docs/agent/운영모드-정상화-구현계획.md), on every path. */
    @Bean(name = "contexaSessionTrackingFilter")
    @ConditionalOnMissingBean(SessionTrackingFilter.class)
    public ContexaSlotFilterRegistration<SessionTrackingFilter> sessionTrackingFilter(
            SessionManagementService contexaSessionManagementService,
            ActiveSessionRepository activeSessionRepository,
            @Qualifier("contexaTrackedSessionMarks") TrackedSessionMarks contexaTrackedSessionMarks,
            ObjectProvider<SecurityProperties> securityProperties) {
        return ContexaServletFilterOrder.member(new SessionTrackingFilter(contexaSessionManagementService,
                        activeSessionRepository, contexaTrackedSessionMarks), "contexaSessionTrackingFilter",
                ContexaServletFilterOrder.securityFilterOrder(securityProperties), ContexaServletFilterOrder.SESSION_TRACKING);
    }

    /** K73: a tracked session whose HTTP session ends, or whose id is replaced, is no longer active. */
    @Bean(name = "contexaActiveSessionEndListener")
    @ConditionalOnMissingBean(name = "contexaActiveSessionEndListener")
    public ServletListenerRegistrationBean<ActiveSessionEndListener> activeSessionEndListener(
            SessionManagementService contexaSessionManagementService,
            @Qualifier("contexaTrackedSessionMarks") TrackedSessionMarks contexaTrackedSessionMarks) {
        return new ServletListenerRegistrationBean<>(new ActiveSessionEndListener(contexaSessionManagementService,
                contexaTrackedSessionMarks));
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
