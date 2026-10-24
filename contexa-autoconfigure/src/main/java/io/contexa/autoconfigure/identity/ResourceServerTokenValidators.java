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
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.properties.OAuth2TokenSettings;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * What Contexa's resource server checks in an access token besides its signature (A1-7, AG-11b): its lifetime, its
 * issuer when issuer validation is on, and its audience when audiences are configured. A token failing any check is
 * refused with 401 before any Contexa decision. Spring's validators do the checking.
 */
final class ResourceServerTokenValidators {

    private ResourceServerTokenValidators() {
    }

    /**
     * @param settings       the OAuth2 settings
     * @param expectedIssuer the issuer the authorization server issues under; no issuer check without one
     */
    static OAuth2TokenValidator<Jwt> of(OAuth2TokenSettings settings, String expectedIssuer) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        if (settings.isIssuerValidationEnabled() && StringUtils.hasText(expectedIssuer)) {
            validators.add(new JwtIssuerValidator(expectedIssuer.trim()));
        }
        List<String> audiences = settings.getAudiences() != null ? List.copyOf(settings.getAudiences()) : List.of();
        if (!audiences.isEmpty()) {
            validators.add(new JwtClaimValidator<Object>(JwtClaimNames.AUD, audience -> namesAnyOf(audience, audiences)));
        }
        return validators.isEmpty() ? JwtValidators.createDefault() : JwtValidators.createDefaultWithValidators(validators);
    }

    private static boolean namesAnyOf(Object audience, List<String> accepted) {
        if (audience instanceof Collection<?> named) {
            return named.stream().anyMatch(value -> value != null && accepted.contains(value.toString()));
        }
        return audience != null && accepted.contains(audience.toString());
    }
}
