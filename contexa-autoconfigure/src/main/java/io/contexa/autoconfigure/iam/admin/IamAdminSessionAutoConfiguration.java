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

import io.contexa.contexacore.autonomous.service.IForceLogoutService;
import io.contexa.contexaiam.admin.web.auth.controller.SessionManagementController;
import io.contexa.contexaiam.admin.web.auth.service.ActiveSessionReferences;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Import;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcOperations;

@AutoConfiguration
@Import(IamAdminSessionContexaOwnedConfiguration.class)
public class IamAdminSessionAutoConfiguration {

    @Bean(name = "contexaSessionManagementService")
    @ConditionalOnMissingBean
    public SessionManagementService sessionManagementService(
            ActiveSessionRepository activeSessionRepository,
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperations,
            ObjectProvider<IForceLogoutService> forceLogout) {
        JdbcOperations jdbc = jdbcOperations.getIfAvailable();
        // Ending a session ends what keeps its person in, as a changed password or a disabled account does.
        return new SessionManagementService(activeSessionRepository,
                jdbc != null ? new ActiveSessionReferences(jdbc) : null, forceLogout::getIfAvailable);
    }

    /**
     * The tracked sessions a database kept under their raw identifiers move to their references when the application
     * starts, before it serves a request, and again whenever the console reads the sessions (a node not yet on
     * references goes on writing the raw value); once moved, nothing is left to move.
     */
    @Bean(name = "contexaActiveSessionReferences")
    public SmartInitializingSingleton contexaActiveSessionReferences(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperations) {
        return () -> {
            JdbcOperations jdbc = jdbcOperations.getIfAvailable();
            if (jdbc != null) {
                new ActiveSessionReferences(jdbc).atStart();
            }
        };
    }

    @Bean(name = "contexaSessionManagementController")
    @ConditionalOnMissingBean
    public SessionManagementController sessionManagementController(
            SessionManagementService contexaSessionManagementService,
            MessageSource messageSource,
            CsvExportService contexaCsvExportService) {
        return new SessionManagementController(contexaSessionManagementService, messageSource, contexaCsvExportService);
    }

}

