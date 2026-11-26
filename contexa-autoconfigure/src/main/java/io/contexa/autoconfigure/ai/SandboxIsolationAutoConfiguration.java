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
package io.contexa.autoconfigure.ai;

import io.contexa.autoconfigure.compat.BootDefaultUserPropertySource;
import io.contexa.contexacommon.operating.ConditionalOnMode;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.ConfigurationCondition;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

import java.util.Arrays;
import java.util.List;

/**
 * The isolation of an existing application that has no Spring Security of its own (R-15 of
 * docs/agent/운영모드-정상화-구현계획.md). Contexa needs Spring Security on the class path, and Spring Boot then gives an
 * application without a chain of its own a default chain that asks every request for a sign-in nobody of the application
 * can complete. With mode SANDBOX, an application that declares neither a chain nor users of its own gets this chain in
 * its place: every request is let through, as before Contexa came. The chain holds no filter at all, so none of what Spring
 * Security's default configuration adds to a chain touches the application's requests: no CSRF, CORS, headers or request
 * cache, no logout (an application's own {@code /logout} reaches the application), no servlet API wrapper (the
 * container's {@code getRemoteUser()}, {@code getUserPrincipal()} and {@code isUserInRole()} stay the container's), no
 * session management (URL rewriting of the session and the session id stay the application's), no security context
 * filter (a user the application put into the security context in front of the chains stays there), no anonymous user
 * and no exception translation (a {@code @Protectable} call refused for want of a user is answered by
 * {@code ProtectableRefusalFilter}, with 401). It stands last, so Contexa's own chains before it keep their paths; Contexa
 * enforces its decisions behind it, from servlet filters. Spring Security's firewall, which its filter chain proxy applies
 * to every request whatever the chains, stays Spring Security's standard. An application with users of its own but no
 * chain keeps Spring Boot's default chain, which is its security.
 */
@AutoConfiguration(beforeName = "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(SecurityFilterChain.class)
@ConditionalOnMode(SecurityMode.SANDBOX)
public class SandboxIsolationAutoConfiguration {

    public static final String ISOLATION_CHAIN = "contexaSandboxIsolationChain";

    @Bean(ISOLATION_CHAIN)
    @Order(Ordered.LOWEST_PRECEDENCE)
    @Conditional(NoApplicationSecurityCondition.class)
    public SecurityFilterChain contexaSandboxIsolationChain() {
        return new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE);
    }

    /**
     * No security chain and no users of the application's own. The application's users are its beans (a user store, a
     * provider, a manager; Contexa's bean names start with "contexa") or Spring Boot's user named by the application's own
     * settings ({@code spring.security.user.name} or {@code .password}), past the source that names Boot's user for Contexa
     * ({@link BootDefaultUserPropertySource#SOURCE_NAME}). Spring Boot's user with neither, whose password Boot makes anew at
     * each start, is not taken for the application's way of signing in.
     */
    static final class NoApplicationSecurityCondition extends SpringBootCondition implements ConfigurationCondition {

        private static final List<Class<?>> APPLICATION_SECURITY = List.of(SecurityFilterChain.class, UserDetailsService.class,
                AuthenticationProvider.class, AuthenticationManager.class);
        private static final List<String> BOOT_USER = List.of("spring.security.user.name", "spring.security.user.password");

        @Override
        public ConfigurationPhase getConfigurationPhase() {
            return ConfigurationPhase.REGISTER_BEAN;
        }

        @Override
        public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
            ConditionMessage.Builder message = ConditionMessage.forCondition("Contexa SANDBOX isolation");
            if (context.getBeanFactory() == null) {
                return ConditionOutcome.noMatch(message.because("no bean factory"));
            }
            List<String> application = APPLICATION_SECURITY.stream()
                    .flatMap(type -> Arrays.stream(context.getBeanFactory().getBeanNamesForType(type, true, false)))
                    .filter(name -> !name.startsWith("contexa"))
                    .toList();
            if (!application.isEmpty()) {
                return ConditionOutcome.noMatch(message.because("the application declares " + application));
            }
            String bootUser = bootUserNamedByTheApplication(context.getEnvironment());
            return bootUser == null
                    ? ConditionOutcome.match(message.because("the application declares no security chain and no users"))
                    : ConditionOutcome.noMatch(message.because("the application sets " + bootUser));
        }

        @Nullable
        static String bootUserNamedByTheApplication(@Nullable Environment environment) {
            if (!(environment instanceof ConfigurableEnvironment configurable)) {
                return null;
            }
            for (PropertySource<?> source : configurable.getPropertySources()) {
                if (BootDefaultUserPropertySource.SOURCE_NAME.equals(source.getName())
                        || ConfigurationPropertySources.isAttachedConfigurationPropertySource(source)) {
                    continue;
                }
                for (String key : BOOT_USER) {
                    if (source.containsProperty(key)) {
                        return key;
                    }
                }
            }
            return null;
        }
    }
}
