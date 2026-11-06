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

import io.contexa.contexacommon.store.ApplicationNamespace;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;

/**
 * Binds the name of the application ({@code spring.application.name}) as the namespace of the keys Contexa keeps in Redis
 * and of its Kafka consumer group, before any bean exists, so that no key is made without it. It runs after the
 * configuration files are read, which is where the name usually comes from.
 */
public class ApplicationNamespacePostProcessor implements EnvironmentPostProcessor, Ordered {

    static final String APPLICATION_NAME_PROPERTY = "spring.application.name";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        ApplicationNamespace.configure(environment.getProperty(APPLICATION_NAME_PROPERTY));
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
