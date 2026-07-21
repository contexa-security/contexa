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
package io.contexa.autoconfigure.core.infra;

import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import org.springframework.boot.autoconfigure.AutoConfigurationImportFilter;
import org.springframework.boot.autoconfigure.AutoConfigurationMetadata;
import org.springframework.boot.jdbc.EmbeddedDatabaseConnection;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

/**
 * Filters out Redis/Kafka/Redisson auto-configurations in standalone mode.
 * Uses pattern-based matching instead of hardcoded FQCNs,
 * so Spring Boot version changes or new auto-configurations are handled automatically.
 */
public class StandaloneAutoConfigurationFilter implements AutoConfigurationImportFilter, EnvironmentAware {

    private static final String MODE_PROPERTY = "contexa.infrastructure.mode";

    private static final String[] EXCLUDE_PATTERNS = {"redis", "kafka", "redisson"};
    private static final String CONTEXA_PACKAGE_PREFIX = "io.contexa.";
    private static final String CONTEXA_OWNED_DATASOURCE_AUTO_CONFIGURATION =
            "io.contexa.autoconfigure.core.ContexaOwnedDataSourceAutoConfiguration";

    private Environment environment;

    @Override
    public boolean[] match(String[] autoConfigurationClasses, AutoConfigurationMetadata metadata) {
        boolean isStandalone = "standalone".equalsIgnoreCase(
                environment.getProperty(MODE_PROPERTY, "standalone"));
        boolean contexaPlatformActive = isContexaPlatformActive();

        boolean[] result = new boolean[autoConfigurationClasses.length];
        for (int i = 0; i < autoConfigurationClasses.length; i++) {
            String autoConfigurationClass = autoConfigurationClasses[i];
            if (autoConfigurationClass == null) {
                result[i] = true;
                continue;
            }

            if (!contexaPlatformActive) {
                if (isContexaOwnedDataSourceAutoConfiguration(autoConfigurationClass)) {
                    result[i] = hasContexaOwnedDataSource();
                } else if (isContexaAutoConfiguration(autoConfigurationClass)) {
                    result[i] = false;
                } else if ("org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration".equals(autoConfigurationClass) ||
                           "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration".equals(autoConfigurationClass) ||
                           "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration".equals(autoConfigurationClass) ||
                           "org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration".equals(autoConfigurationClass)) {
                    boolean hasUrl = environment.containsProperty("spring.datasource.url") || hasContexaOwnedDataSource();
                    boolean hasEmbedded = EmbeddedDatabaseConnection.get(getClass().getClassLoader()) != EmbeddedDatabaseConnection.NONE;
                    result[i] = hasUrl || hasEmbedded;
                } else {
                    result[i] = true;
                }
                continue;
            }

            if (isStandalone) {
                String lowerName = autoConfigurationClass.toLowerCase();
                boolean excluded = false;
                for (String pattern : EXCLUDE_PATTERNS) {
                    if (lowerName.contains(pattern)) {
                        excluded = true;
                        break;
                    }
                }
                result[i] = !excluded;
            } else {
                result[i] = true;
            }
        }
        return result;
    }

    private boolean isContexaPlatformActive() {
        return environment != null && environment.containsProperty(AiSecurityImportSelector.PROP_MODE);
    }

    private boolean isContexaAutoConfiguration(String autoConfigurationClass) {
        return autoConfigurationClass.startsWith(CONTEXA_PACKAGE_PREFIX);
    }

    private boolean isContexaOwnedDataSourceAutoConfiguration(String autoConfigurationClass) {
        return CONTEXA_OWNED_DATASOURCE_AUTO_CONFIGURATION.equals(autoConfigurationClass);
    }

    private boolean hasContexaOwnedDataSource() {
        return environment != null
                && environment.containsProperty("contexa.datasource.url")
                && environment.getProperty(
                        "contexa.datasource.isolation.contexa-owned-application",
                        Boolean.class,
                        false);
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }
}
