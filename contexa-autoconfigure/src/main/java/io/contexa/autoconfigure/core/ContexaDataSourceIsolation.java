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
package io.contexa.autoconfigure.core;

import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.util.StringUtils;

final class ContexaDataSourceIsolation {

    private ContexaDataSourceIsolation() {
    }

    static void validate(ContexaDataSourceProperties properties, Environment environment) {
        String contexaUrl = normalize(properties.getUrl());
        if (!StringUtils.hasText(contexaUrl)) {
            throw new IllegalStateException("contexa.datasource.url must be configured for @EnableAISecurity. "
                    + "Use a dedicated Contexa database by default; sharing the application database requires explicit POC approval.");
        }

        String applicationUrl = normalize(environment.getProperty("spring.datasource.url"));
        if (!StringUtils.hasText(applicationUrl) || !contexaUrl.equals(applicationUrl)) {
            return;
        }

        ContexaDataSourceProperties.Isolation isolation = properties.getIsolation();
        if (isolation.isContexaOwnedApplication()) {
            return;
        }

        boolean sharedApproved = isolation.isAllowSharedApplicationDatasource()
                && isolation.isSharedApplicationDatasourceRiskAccepted();
        if (isProduction(environment)) {
            throw new IllegalStateException("contexa.datasource must not share the application datasource in production profiles");
        }
        if (!sharedApproved) {
            throw new IllegalStateException("contexa.datasource must not share spring.datasource unless "
                    + "contexa.datasource.isolation.allow-shared-application-datasource=true and "
                    + "contexa.datasource.isolation.shared-application-datasource-risk-accepted=true are both set for an approved POC");
        }
    }

    private static boolean isProduction(Environment environment) {
        return environment.acceptsProfiles(Profiles.of("prod", "production"));
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
