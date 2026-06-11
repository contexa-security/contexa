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
package io.contexa.contexacommon.security.bridge.handoff;

import org.springframework.lang.Nullable;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;

public record ContexaAuthHandoff(
        Object principal,
        Collection<?> authorities,
        Map<String, Object> attributes,
        String authenticationType,
        String authenticationAssurance,
        Boolean mfaVerified
) {

    public ContexaAuthHandoff {
        if (principal == null) {
            throw new IllegalArgumentException("principal must not be null");
        }
        authorities = authorities == null ? java.util.List.of() : java.util.List.copyOf(new LinkedHashSet<>(authorities));
        attributes = attributes == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(attributes));
    }

    public static ContexaAuthHandoff of(Object principal) {
        return new ContexaAuthHandoff(principal, java.util.List.of(), Map.of(), null, null, null);
    }

    public static ContexaAuthHandoff of(Object principal, Collection<?> authorities) {
        return new ContexaAuthHandoff(principal, authorities, Map.of(), null, null, null);
    }

    public static ContexaAuthHandoff of(Object principal, Collection<?> authorities, Map<String, Object> attributes) {
        return new ContexaAuthHandoff(principal, authorities, attributes, null, null, null);
    }

    public ContexaAuthHandoff withAuthenticationType(@Nullable String authenticationType) {
        return new ContexaAuthHandoff(principal, authorities, attributes, authenticationType, authenticationAssurance, mfaVerified);
    }

    public ContexaAuthHandoff withAuthenticationAssurance(@Nullable String authenticationAssurance) {
        return new ContexaAuthHandoff(principal, authorities, attributes, authenticationType, authenticationAssurance, mfaVerified);
    }

    public ContexaAuthHandoff withMfaVerified(@Nullable Boolean mfaVerified) {
        return new ContexaAuthHandoff(principal, authorities, attributes, authenticationType, authenticationAssurance, mfaVerified);
    }
}