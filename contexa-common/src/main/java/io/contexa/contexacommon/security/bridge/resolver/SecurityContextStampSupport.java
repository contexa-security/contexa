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

import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationToken;
import io.contexa.contexacommon.security.bridge.authentication.BridgePrincipal;
import io.contexa.contexacommon.security.bridge.identity.BridgeObjectExtractor;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

final class SecurityContextStampSupport {

    private SecurityContextStampSupport() {
    }

    /**
     * The application's subject of an authentication, by the one rule Zero Trust keys its decisions by
     * ({@link ContexaIdentity#subjectId}, R-10): a key of the principal or its details named some other user ID, and the
     * stamp and the copy of the user were then another subject than the decisions (analysis L-05). An authentication
     * Contexa made from a bridge stamp is read back as the application's subject it was made from: its name is the
     * account of the copy where Contexa signs the users in, and a stamp of that name made a copy of the copy.
     */
    static String extractPrincipalId(Authentication authentication) {
        if (authentication instanceof BridgeAuthenticationToken bridged) {
            String madeFrom = bridged.getPrincipal() instanceof BridgePrincipal principal
                    ? text(principal.principalId())
                    : null;
            if (madeFrom == null && bridged.getDetails() != null) {
                madeFrom = text(bridged.getDetails().externalSubjectId());
            }
            if (madeFrom != null) {
                return madeFrom;
            }
        }
        return ContexaIdentity.subjectId(authentication);
    }

    static String extractString(Authentication authentication, List<String> keys) {
        String fromDetails = BridgeObjectExtractor.extractString(authentication != null ? authentication.getDetails() : null, keys);
        if (fromDetails != null) {
            return fromDetails;
        }
        return BridgeObjectExtractor.extractString(authentication != null ? authentication.getPrincipal() : null, keys);
    }

    static Boolean extractBoolean(Authentication authentication, List<String> keys) {
        Boolean fromDetails = BridgeObjectExtractor.extractBoolean(authentication != null ? authentication.getDetails() : null, keys);
        if (fromDetails != null) {
            return fromDetails;
        }
        return BridgeObjectExtractor.extractBoolean(authentication != null ? authentication.getPrincipal() : null, keys);
    }

    static Instant extractInstant(Authentication authentication, List<String> keys) {
        Instant fromDetails = BridgeObjectExtractor.extractInstant(authentication != null ? authentication.getDetails() : null, keys);
        if (fromDetails != null) {
            return fromDetails;
        }
        return BridgeObjectExtractor.extractInstant(authentication != null ? authentication.getPrincipal() : null, keys);
    }

    static List<String> extractStringList(Authentication authentication, List<String> keys) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        values.addAll(BridgeObjectExtractor.extractStringSet(authentication != null ? authentication.getDetails() : null, keys));
        values.addAll(BridgeObjectExtractor.extractStringSet(authentication != null ? authentication.getPrincipal() : null, keys));
        return List.copyOf(values);
    }

    static Map<String, Object> extractAttributes(Object source, List<String> keys) {
        return BridgeObjectExtractor.extractAttributes(source, keys);
    }

    static Map<String, Object> mergeAttributes(Object primary, Object secondary, List<String> keys) {
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.putAll(extractAttributes(primary, keys));
        attributes.putAll(extractAttributes(secondary, keys));
        return Map.copyOf(attributes);
    }

    static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }
}


