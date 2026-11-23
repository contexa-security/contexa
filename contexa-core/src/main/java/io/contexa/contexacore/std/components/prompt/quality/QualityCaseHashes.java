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
package io.contexa.contexacore.std.components.prompt.quality;

import com.fasterxml.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

/**
 * The content hashes of labelled cases and of a set of them (plan 3.2). The hash reads the structured values, not
 * their text: object fields in the order of their names, whole numbers by their digits and fractional numbers by the
 * bits of their double value, so the same content has the same hash whatever wrote the text and on whichever Java.
 */
final class QualityCaseHashes {

    private static final String CASE_SCHEME = "contexa-quality-case-1";
    private static final String SET_SCHEME = "contexa-quality-case-set-1";

    private QualityCaseHashes() {
    }

    static String caseHash(QualityCase item) {
        MessageDigest digest = sha256();
        text(digest, CASE_SCHEME);
        text(digest, item.key());
        QualityCaseInput input = item.input();
        node(digest, input.canonicalContext());
        node(digest, input.requestFacts());
        node(digest, input.authState());
        node(digest, input.baselineSnapshot());
        node(digest, input.ragResults());
        node(digest, input.pastDeniedDecisions());
        node(digest, input.personalBaseline());
        node(digest, input.organizationBaseline());
        QualityCaseExpectation expectation = item.expectation();
        mark(digest, '[');
        // The allowed actions are an enum set, so they come in the order of the enum.
        expectation.allowedActions().forEach(action -> text(digest, action.name()));
        mark(digest, ']');
        text(digest, expectation.preferredAction() != null ? expectation.preferredAction().name() : null);
        text(digest, expectation.classification().name());
        text(digest, expectation.kind().name());
        text(digest, expectation.rationale().korean());
        text(digest, expectation.rationale().english());
        mark(digest, '[');
        expectation.decidingFacts().forEach(fact -> text(digest, fact));
        mark(digest, ']');
        text(digest, item.grade().name());
        text(digest, item.rootCaseKey());
        text(digest, item.environment().timeZone());
        text(digest, item.environment().contextFormatVersion());
        return HexFormat.of().formatHex(digest.digest());
    }

    static String setVersion(List<QualityCase> cases) {
        List<QualityCase> ordered = new ArrayList<>(cases);
        ordered.sort(Comparator.comparing(QualityCase::key));
        MessageDigest digest = sha256();
        text(digest, SET_SCHEME);
        for (QualityCase item : ordered) {
            text(digest, item.key());
            text(digest, caseHash(item));
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void node(MessageDigest digest, JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            mark(digest, 'N');
        }
        else if (node.isObject()) {
            List<String> names = new ArrayList<>();
            node.fieldNames().forEachRemaining(names::add);
            names.sort(Comparator.naturalOrder());
            mark(digest, '{');
            for (String name : names) {
                text(digest, name);
                node(digest, node.get(name));
            }
            mark(digest, '}');
        }
        else if (node.isArray()) {
            mark(digest, '[');
            node.forEach(item -> node(digest, item));
            mark(digest, ']');
        }
        else if (node.isBoolean()) {
            mark(digest, node.booleanValue() ? 'T' : 'F');
        }
        else if (node.isIntegralNumber()) {
            mark(digest, 'I');
            digest.update(node.bigIntegerValue().toString().getBytes(StandardCharsets.US_ASCII));
            mark(digest, ';');
        }
        else if (node.isNumber()) {
            mark(digest, 'D');
            digest.update(HexFormat.of().toHexDigits(Double.doubleToLongBits(node.doubleValue()))
                    .getBytes(StandardCharsets.US_ASCII));
        }
        else {
            text(digest, node.asText());
        }
    }

    /** A text by its length and bytes, so two texts never read as one; null is its own mark. */
    private static void text(MessageDigest digest, String value) {
        if (value == null) {
            mark(digest, 'N');
            return;
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        mark(digest, 'S');
        digest.update(Integer.toString(bytes.length).getBytes(StandardCharsets.US_ASCII));
        mark(digest, ':');
        digest.update(bytes);
    }

    private static void mark(MessageDigest digest, char mark) {
        digest.update((byte) mark);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 algorithm is not available.", exception);
        }
    }
}
