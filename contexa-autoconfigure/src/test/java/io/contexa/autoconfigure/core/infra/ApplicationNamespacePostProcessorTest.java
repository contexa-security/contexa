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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.event.ApplicationPreparedEvent;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.mock.env.MockEnvironment;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;

import static org.assertj.core.api.Assertions.assertThat;

/** The name of the application is bound before any bean exists, from where Spring Boot reads it. */
class ApplicationNamespacePostProcessorTest {

    @Configuration(proxyBeanMethods = false)
    static class Nothing {
    }

    @Test
    @DisplayName("spring.application.name is the namespace, lower case")
    void theNameIsBound() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            MockEnvironment environment = new MockEnvironment().withProperty("spring.application.name", "PetClinic-A");
            new ApplicationNamespacePostProcessor().postProcessEnvironment(environment, null);

            assertThat(ApplicationNamespace.identifier()).isEqualTo("petclinic-a");
        }
    }

    @Test
    @DisplayName("an application with no name has none, even after another was bound")
    void noNameUnbinds() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("left-over")) {
            new ApplicationNamespacePostProcessor().postProcessEnvironment(new MockEnvironment(), null);

            assertThat(ApplicationNamespace.isNamed()).isFalse();
        }
    }

    @Test
    @DisplayName("a placeholder in the name is resolved")
    void aPlaceholderIsResolved() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            MockEnvironment environment = new MockEnvironment()
                    .withProperty("spring.application.name", "${SERVICE_NAME:orders}");
            new ApplicationNamespacePostProcessor().postProcessEnvironment(environment, null);

            assertThat(ApplicationNamespace.identifier()).isEqualTo("orders");
        }
    }

    @Test
    @DisplayName("an application started by Spring Boot has its name bound by the time its beans are created")
    void springBootBindsTheNameAtTheStart() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            String[] boundWhenTheContextRefreshes = new String[1];
            try (var context = new SpringApplicationBuilder(Nothing.class)
                    .web(WebApplicationType.NONE)
                    .properties("spring.application.name=Shop-Front")
                    .listeners(event -> {
                        if (event instanceof ApplicationPreparedEvent) {
                            boundWhenTheContextRefreshes[0] = ApplicationNamespace.identifier();
                        }
                    })
                    .run()) {
                assertThat(boundWhenTheContextRefreshes[0]).isEqualTo("shop-front");
                assertThat(ApplicationNamespace.key("k")).isEqualTo("ctxa:shop-front:k");
            }
        }
    }

    @Test
    @DisplayName("the processor is registered both ways Spring Boot reads it, and runs after the configuration files")
    void itIsRegistered() throws IOException {
        boolean inFactories = false;
        for (Enumeration<URL> files = getClass().getClassLoader().getResources("META-INF/spring.factories");
             files.hasMoreElements(); ) {
            try (InputStream in = files.nextElement().openStream()) {
                inFactories |= new String(in.readAllBytes(), StandardCharsets.UTF_8)
                        .contains(ApplicationNamespacePostProcessor.class.getName());
            }
        }
        assertThat(inFactories).as("META-INF/spring.factories").isTrue();
        try (InputStream imports = getClass().getClassLoader().getResourceAsStream(
                "META-INF/spring/org.springframework.boot.env.EnvironmentPostProcessor.imports")) {
            assertThat(new String(imports.readAllBytes(), StandardCharsets.UTF_8))
                    .contains(ApplicationNamespacePostProcessor.class.getName());
        }
        assertThat(new ApplicationNamespacePostProcessor().getOrder())
                .isGreaterThan(Ordered.HIGHEST_PRECEDENCE + 10);
    }
}
