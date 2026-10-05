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
package io.contexa.autoconfigure.compat;

import io.contexa.autoconfigure.core.infra.ContexaPlatformActivation;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Property source for values contributed by Contexa environment post-processors.
 *
 * <p>Environment post-processors run before {@code @EnableAISecurity} is processed, so they cannot know
 * whether the host application activates the platform. Keys in the {@code contexa.*} namespace are always
 * visible. Every other key (Spring AI, Spring Boot management, ...) is resolved at lookup time and is only
 * visible while {@link ContexaPlatformActivation#isActive(Environment)} holds, which keeps dependency-only
 * applications free of Contexa defaults.</p>
 *
 * <p>Names outside this source's own key set return {@code null} without consulting the Environment, so the
 * activation lookup (which iterates all property sources, including this one) cannot recurse.</p>
 *
 * <p>Spring Boot may replace the Environment instance after the post-processors ran (for example when
 * {@code spring.main.web-application-type} changes the environment type). The property source instances are
 * carried over, so {@link PlatformActivationGatedPropertySourceBinder} re-binds them to the Environment of the
 * application context before {@code @EnableAISecurity} publishes its activation property.</p>
 */
final class PlatformActivationGatedPropertySource extends EnumerablePropertySource<Map<String, Object>> {

    private static final String CONTEXA_PREFIX = "contexa.";

    private volatile Environment environment;

    private final String[] propertyNames;

    PlatformActivationGatedPropertySource(String name, Map<String, Object> properties, Environment environment) {
        super(name, Collections.unmodifiableMap(new LinkedHashMap<>(properties)));
        this.environment = environment;
        this.propertyNames = getSource().keySet().toArray(new String[0]);
    }

    void bindTo(Environment environment) {
        this.environment = environment;
    }

    @Override
    public Object getProperty(String name) {
        Object value = getSource().get(name);
        if (value == null) {
            return null;
        }
        if (isAlwaysVisible(name) || ContexaPlatformActivation.isActive(environment)) {
            return value;
        }
        return null;
    }

    @Override
    public boolean containsProperty(String name) {
        return getProperty(name) != null;
    }

    @Override
    public String[] getPropertyNames() {
        return propertyNames.clone();
    }

    static boolean isAlwaysVisible(String name) {
        return name.startsWith(CONTEXA_PREFIX);
    }
}
