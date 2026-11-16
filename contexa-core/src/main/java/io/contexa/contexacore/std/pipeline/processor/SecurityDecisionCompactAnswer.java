/*
 * Copyright 2026 The Contexa Project
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *   https://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.pipeline.processor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * The short answer of the output contract v5 (v1.0, K30) as the v21 response check reads an answer. A v5 answer names
 * only the explanation it judged most likely ({@code hypothesis}); the check reads the explanations of a v4 answer
 * ({@code hypotheses}), so the answer is handed to it with that one explanation as the list, with no fact lists. The
 * check's own code stays as v21 and the v1.0 variants hash it in their bundles (B6); the answer the decision records
 * stays as it came.
 */
public final class SecurityDecisionCompactAnswer {

    /** The request parameter a strategy sets when the event's bundle answers in the output contract v5. */
    public static final String REQUEST_PARAMETER = "securityDecisionCompactAnswer";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SecurityDecisionCompactAnswer() {
    }

    /**
     * The answer with its one explanation as the list of explanations the check reads; the answer as it is when it has
     * no JSON object, already has the list, or names no explanation (the check then finds the explanation missing).
     */
    public static String withExplanations(String rawResponse) {
        if (rawResponse == null) {
            return null;
        }
        int start = rawResponse.indexOf('{');
        int end = rawResponse.lastIndexOf('}');
        if (start < 0 || end <= start) {
            return rawResponse;
        }
        try {
            JsonNode node = MAPPER.readTree(rawResponse.substring(start, end + 1));
            if (!(node instanceof ObjectNode answer) || answer.has("hypotheses")) {
                return rawResponse;
            }
            JsonNode named = answer.get("hypothesis");
            if (named == null || named.isNull() || named.asText().isBlank()) {
                return rawResponse;
            }
            ObjectNode explanation = MAPPER.createObjectNode();
            explanation.put("id", named.asText().trim());
            explanation.putNull("name");
            explanation.put("assessment", "MOST_LIKELY");
            explanation.putArray("for");
            explanation.putArray("against");
            ArrayNode explanations = answer.putArray("hypotheses");
            explanations.add(explanation);
            return MAPPER.writeValueAsString(answer);
        }
        catch (Exception unreadable) {
            return rawResponse;
        }
    }

    /** The hash of an answer as the output parser writes it, so a record names the answer as it came. */
    public static String hashOf(String rawResponse) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((rawResponse != null ? rawResponse : "").getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder("sha256:");
            for (byte b : hash) {
                builder.append(String.format(Locale.ROOT, "%02x", b));
            }
            return builder.toString();
        }
        catch (Exception unavailable) {
            return "sha256:unavailable";
        }
    }
}
