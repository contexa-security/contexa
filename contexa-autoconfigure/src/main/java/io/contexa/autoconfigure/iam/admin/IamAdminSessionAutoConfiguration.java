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

import io.contexa.contexaiam.admin.web.auth.controller.SessionManagementController;
import io.contexa.contexaiam.admin.web.auth.filter.SessionTrackingFilter;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class IamAdminSessionAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SessionManagementService sessionManagementService(
            ActiveSessionRepository activeSessionRepository) {
        return new SessionManagementService(activeSessionRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionManagementController sessionManagementController(
            SessionManagementService sessionManagementService,
            ActiveSessionRepository activeSessionRepository,
            MessageSource messageSource,
            CsvExportService csvExportService) {
        return new SessionManagementController(sessionManagementService, activeSessionRepository, messageSource, csvExportService);
    }

    @Bean
    @ConditionalOnMissingBean(SessionTrackingFilter.class)
    public FilterRegistrationBean<SessionTrackingFilter> sessionTrackingFilter(
            SessionManagementService sessionManagementService,
            ActiveSessionRepository activeSessionRepository) {
        FilterRegistrationBean<SessionTrackingFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new SessionTrackingFilter(sessionManagementService, activeSessionRepository));
        registration.addUrlPatterns("/*");
        registration.setName("sessionTrackingFilter");
        registration.setOrder(200);
        return registration;
    }
}

