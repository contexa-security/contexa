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

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.PasskeyUrls;
import org.springframework.core.env.Environment;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.security.web.webauthn.management.Webauthn4JRelyingPartyOperations;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The one place that builds Spring Security's webauthn4j relying party. It is touched only when webauthn4j is on the class
 * path ({@code PasskeyLibrary}): building the relying party loads webauthn4j and its CBOR codec, which an application may
 * have excluded. Nothing else in Contexa names the class.
 */
final class Webauthn4jRelyingParty {

    private Webauthn4jRelyingParty() {
    }

    /** The same relying party as Contexa's own passkey factor ({@code contexa.auth.urls.factors.passkey.*}). */
    static WebAuthnRelyingPartyOperations create(PublicKeyCredentialUserEntityRepository entities,
                                                 UserCredentialRepository credentials,
                                                 AuthContextProperties properties, Environment environment) {
        PasskeyUrls passkey = properties.getUrls().getFactors().getPasskey();
        String configured = passkey.getAllowedOrigins();
        Set<String> origins = configured != null && !configured.isBlank()
                ? Arrays.stream(configured.split(",")).map(String::trim).filter(o -> !o.isEmpty())
                .collect(Collectors.toSet())
                : Set.of("http://localhost:" + environment.getProperty("server.port", "8080"));
        return new Webauthn4JRelyingPartyOperations(entities, credentials,
                PublicKeyCredentialRpEntity.builder().id(passkey.getRpId()).name(passkey.getRpName()).build(),
                origins);
    }
}
