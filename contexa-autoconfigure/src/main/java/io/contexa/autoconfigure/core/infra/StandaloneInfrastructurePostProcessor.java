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

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.Map;

/**
 * Sets standalone-specific properties when contexa.infrastructure.mode=standalone (default).
 * Auto-configuration filtering is handled by StandaloneAutoConfigurationFilter.
 */
public class StandaloneInfrastructurePostProcessor implements EnvironmentPostProcessor {

    private static final String MODE_PROPERTY = "contexa.infrastructure.mode";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String mode = environment.getProperty(MODE_PROPERTY, "standalone");
        if (!"standalone".equalsIgnoreCase(mode)) {
            return;
        }

        environment.getPropertySources().addFirst(
                new MapPropertySource("standaloneInfrastructureDefaults",
                        Map.of("contexa.cache.type", "LOCAL")));
    }
}
