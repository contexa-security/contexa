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
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.util.ClassUtils;

import java.util.List;
import java.util.Locale;

/**
 * Keeps the user Spring Boot makes for an application secured by Boot's defaults (PR-5).
 *
 * <p>Boot gives that user up as soon as the OAuth2 client or resource server classes are on the class path, reading them
 * as the application's way of signing in. The starter brings those classes for what Contexa does once it is on, so an
 * application with only the dependency lost its user and nobody could sign in. Boot keeps the user when the application
 * names it. This source names it, with the name Boot itself defaults to: the password stays generated and Boot's line at
 * the start stays the same.</p>
 *
 * <p>It stays silent where the user is not the application's way of signing in: when Contexa owns the sign-in, and when the
 * application's settings configure OAuth2 or SAML, which is what Boot's class check stands for. An application that signs
 * in through OAuth2 with beans of its own, and no such settings, keeps a user nobody knows the password of.</p>
 *
 * <p>The answer is read at each lookup, because environment post-processors run before {@code @EnableAISecurity} is
 * processed. Only the one name is answered, so a lookup of anything else costs nothing and a lookup cannot recurse.</p>
 */
final class BootDefaultUserPropertySource extends PropertySource<Object> {

    static final String SOURCE_NAME = "contexaBootDefaultUser";

    private static final String USER_NAME = "spring.security.user.name";
    private static final String BOOT_DEFAULT_NAME = "user";
    private static final String HTTP_SECURITY = "org.springframework.security.config.annotation.web.builders.HttpSecurity";
    private static final List<String> OWN_SIGN_IN_PREFIXES = List.of("spring.security.oauth2.", "spring.security.saml2.");

    private volatile Environment environment;

    BootDefaultUserPropertySource(Environment environment) {
        super(SOURCE_NAME, new Object());
        this.environment = environment;
    }

    void bindTo(Environment environment) {
        this.environment = environment;
    }

    @Override
    public Object getProperty(String name) {
        return USER_NAME.equals(name) && bootsUserIsTheSignIn() ? BOOT_DEFAULT_NAME : null;
    }

    private boolean bootsUserIsTheSignIn() {
        return ClassUtils.isPresent(HTTP_SECURITY, getClass().getClassLoader())
                && environment instanceof ConfigurableEnvironment configurable
                && !contexaOwnsTheSignIn(configurable)
                && !applicationNamesItsOwnSignIn(configurable);
    }

    private static boolean contexaOwnsTheSignIn(ConfigurableEnvironment environment) {
        PropertySource<?> activation = environment.getPropertySources().get(AiSecurityImportSelector.ACTIVATION_SOURCE);
        return activation != null && SecurityOwnershipMode.CONTEXA_OWNED.name()
                .equals(activation.getProperty(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP));
    }

    private static boolean applicationNamesItsOwnSignIn(ConfigurableEnvironment environment) {
        for (PropertySource<?> source : environment.getPropertySources()) {
            if (source instanceof EnumerablePropertySource<?> enumerable) {
                for (String name : enumerable.getPropertyNames()) {
                    if (namesOwnSignIn(name)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /** In the form of a key or of an environment variable. */
    private static boolean namesOwnSignIn(String name) {
        String key = name.toLowerCase(Locale.ROOT).replace('_', '.');
        return OWN_SIGN_IN_PREFIXES.stream().anyMatch(key::startsWith);
    }
}
