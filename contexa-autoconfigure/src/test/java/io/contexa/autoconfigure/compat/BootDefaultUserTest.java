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

import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-5: an application that signs in with the user Spring Boot makes lost it when only the starter was added, so nobody
 * could sign in. Boot gives that user up as soon as the OAuth2 client classes are on the class path, and the starter brings
 * them for what Contexa does once it is on. These run Boot's own auto-configuration: the OAuth2 classes are on this class
 * path, as in an application with the starter.
 */
@ExtendWith(OutputCaptureExtension.class)
class BootDefaultUserTest {

    private final WebApplicationContextRunner boot = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SecurityAutoConfiguration.class, UserDetailsServiceAutoConfiguration.class));

    private final WebApplicationContextRunner withContexa = boot.withInitializer(BootDefaultUserTest::defaultsOfContexa);

    private static void defaultsOfContexa(ConfigurableApplicationContext context) {
        new ContexaDefaultPropertiesPostProcessor().postProcessEnvironment(context.getEnvironment(), new SpringApplication());
    }

    private static void activated(ConfigurableApplicationContext context, String ownership) {
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource(
                AiSecurityImportSelector.ACTIVATION_SOURCE, Map.of(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP, ownership)));
    }

    @Test
    @DisplayName("what these tests stand on: Spring Boot alone makes no user with the OAuth2 classes on the class path")
    void bootAloneGivesTheUserUp() {
        boot.run(context -> assertThat(context).doesNotHaveBean(UserDetailsService.class));
    }

    @Test
    @DisplayName("with only the dependency the application keeps Boot's user and its generated password")
    void theDependencyAloneLeavesBootsUser(CapturedOutput output) {
        withContexa.run(context -> {
            UserDetails user = context.getBean(UserDetailsService.class).loadUserByUsername("user");

            assertThat(user.getUsername()).isEqualTo("user");
            assertThat(output).contains("Using generated security password");
        });
    }

    @Test
    @DisplayName("a name the application set itself stays its own")
    void aNameOfTheApplicationStays() {
        withContexa.withPropertyValues("spring.security.user.name=operator", "spring.security.user.password=secret")
                .run(context -> assertThat(context.getBean(UserDetailsService.class).loadUserByUsername("operator"))
                        .isNotNull());
    }

    @Test
    @DisplayName("an application that signs in through OAuth2 itself makes no user, as without Contexa")
    void anApplicationOnOAuth2MakesNoUser() {
        withContexa.withPropertyValues("spring.security.oauth2.client.registration.app.client-id=app")
                .run(context -> assertThat(context).doesNotHaveBean(UserDetailsService.class));
        withContexa.withPropertyValues("spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://idp.example/keys")
                .run(context -> assertThat(context).doesNotHaveBean(UserDetailsService.class));
    }

    @Test
    @DisplayName("where the application keeps its sign-in with Contexa on, Boot's user stays")
    void anApplicationThatKeepsItsSignInKeepsTheUser() {
        withContexa.withInitializer(context -> activated(context, "HOST_OWNED"))
                .run(context -> assertThat(context.getBean(UserDetailsService.class).loadUserByUsername("user")).isNotNull());
    }

    @Test
    @DisplayName("where Contexa owns the sign-in, Boot's user is not made")
    void whereContexaOwnsTheSignInBootMakesNoUser() {
        withContexa.withInitializer(context -> activated(context, "CONTEXA_OWNED"))
                .run(context -> assertThat(context).doesNotHaveBean(UserDetailsService.class));
    }
}
