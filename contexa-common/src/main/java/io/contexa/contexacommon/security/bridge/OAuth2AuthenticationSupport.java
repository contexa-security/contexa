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
package io.contexa.contexacommon.security.bridge;

import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationToken;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.ClassUtils;

/**
 * Resolves the bridge principal id of OAuth2/JWT authentications.
 * <p>
 * Zero Trust keys its decisions by {@link Authentication#getName()} (the JWT principal claim, {@code sub} by
 * default, or the OAuth2 user name attribute), so the bridge uses the same value for these authentications.
 * An authentication counts as OAuth2 when it is an {@code AbstractOAuth2TokenAuthenticationToken} or an
 * {@code OAuth2AuthenticationToken}, or when a re-wrapped token (for example the Zero Trust token) still carries
 * an {@code OAuth2AuthenticatedPrincipal}. {@link UserDetails} principals and {@link BridgeAuthenticationToken}
 * keep the existing extraction.
 * <p>
 * The Spring Security OAuth2 modules are optional at runtime, so their types are only referenced from holder
 * classes that are loaded after a class-presence check.
 */
public final class OAuth2AuthenticationSupport {

    private static final ClassLoader CLASS_LOADER = OAuth2AuthenticationSupport.class.getClassLoader();
    private static final boolean OAUTH2_CORE_PRESENT = ClassUtils.isPresent(
            "org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal", CLASS_LOADER);
    private static final boolean RESOURCE_SERVER_PRESENT = ClassUtils.isPresent(
            "org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken",
            CLASS_LOADER);
    private static final boolean OAUTH2_CLIENT_PRESENT = ClassUtils.isPresent(
            "org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken", CLASS_LOADER);

    private OAuth2AuthenticationSupport() {
    }

    /**
     * Returns {@link Authentication#getName()} for an OAuth2/JWT authentication, or {@code null} when the
     * authentication is not OAuth2 or its name is blank.
     */
    @Nullable
    public static String principalName(@Nullable Authentication authentication) {
        if (!isOAuth2Authentication(authentication)) {
            return null;
        }
        String name = authentication.getName();
        if (name == null || name.isBlank()) {
            return null;
        }
        return name.trim();
    }

    public static boolean isOAuth2Authentication(@Nullable Authentication authentication) {
        if (authentication == null || authentication instanceof BridgeAuthenticationToken) {
            return false;
        }
        if (RESOURCE_SERVER_PRESENT && ResourceServerTypes.isOAuth2Token(authentication)) {
            return true;
        }
        if (OAUTH2_CLIENT_PRESENT && OAuth2ClientTypes.isOAuth2Login(authentication)) {
            return true;
        }
        Object principal = authentication.getPrincipal();
        return OAUTH2_CORE_PRESENT
                && !(principal instanceof UserDetails)
                && OAuth2CoreTypes.isOAuth2Principal(principal);
    }

    private static final class ResourceServerTypes {

        private ResourceServerTypes() {
        }

        static boolean isOAuth2Token(Authentication authentication) {
            return authentication instanceof AbstractOAuth2TokenAuthenticationToken<?>;
        }
    }

    private static final class OAuth2ClientTypes {

        private OAuth2ClientTypes() {
        }

        static boolean isOAuth2Login(Authentication authentication) {
            return authentication instanceof OAuth2AuthenticationToken;
        }
    }

    private static final class OAuth2CoreTypes {

        private OAuth2CoreTypes() {
        }

        static boolean isOAuth2Principal(@Nullable Object principal) {
            return principal instanceof OAuth2AuthenticatedPrincipal;
        }
    }
}
