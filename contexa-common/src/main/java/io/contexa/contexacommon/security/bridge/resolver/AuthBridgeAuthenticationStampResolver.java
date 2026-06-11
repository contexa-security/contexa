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
package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.AuthBridge;
import io.contexa.contexacommon.security.bridge.BridgeObjectExtractor;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgedUser;
import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Optional;

public class AuthBridgeAuthenticationStampResolver implements AuthenticationStampResolver {

    private final AuthBridge authBridge;

    public AuthBridgeAuthenticationStampResolver(AuthBridge authBridge) {
        this.authBridge = authBridge;
    }

    @Override
    public Optional<AuthenticationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        if (authBridge == null) {
            return Optional.empty();
        }
        BridgedUser bridgedUser = authBridge.extractUser(request);
        if (bridgedUser == null || bridgedUser.username() == null || bridgedUser.username().isBlank()) {
            return Optional.empty();
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>(bridgedUser.attributes());
        Instant authenticationTime = BridgeObjectExtractor.extractInstant(attributes, java.util.List.of("authenticationTime"));
        Boolean mfaCompleted = BridgeObjectExtractor.extractBoolean(attributes, java.util.List.of("mfaCompleted"));
        String authenticationType = BridgeObjectExtractor.extractString(attributes, java.util.List.of("authenticationType"));
        String authenticationAssurance = BridgeObjectExtractor.extractString(attributes, java.util.List.of("authenticationAssurance"));
        attributes.put("authenticationAssuranceEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(authenticationAssurance));
        attributes.put("mfaCompletedEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(mfaCompleted));
        attributes.put("authenticationTimeEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(authenticationTime));
        return Optional.of(new AuthenticationStamp(
                bridgedUser.username(),
                bridgedUser.displayName(),
                "BRIDGED_USER",
                true,
                authenticationType,
                String.valueOf(attributes.getOrDefault("bridgeAuthenticationSource", authBridge.getClass().getSimpleName())),
                authenticationAssurance,
                mfaCompleted,
                authenticationTime,
                requestContext.sessionId(),
                bridgedUser.roles().stream().toList(),
                attributes
        ));
    }
}

