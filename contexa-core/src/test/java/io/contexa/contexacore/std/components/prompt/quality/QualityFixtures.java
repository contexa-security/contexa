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
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Cases for the tests of the quality measurement, and the rows the local measurement wrote.
 */
final class QualityFixtures {

    static final ObjectMapper JSON = new ObjectMapper();

    static final Set<QualityAction> STOP = EnumSet.of(QualityAction.BLOCK, QualityAction.CHALLENGE,
            QualityAction.ESCALATE);
    static final Set<QualityAction> PASS = EnumSet.of(QualityAction.ALLOW, QualityAction.CHALLENGE);

    private QualityFixtures() {
    }

    /** A threat that is its own root. */
    static QualityCase threat(String key) {
        return threat(key, null);
    }

    /** A threat made from the root. */
    static QualityCase threat(String key, String root) {
        return of(key, root, QualityCaseClass.THREAT, STOP, QualityCaseGrade.ORDINARY, QualityCaseOrigin.CONTEXA, null);
    }

    static QualityCase uncertain(String key) {
        return of(key, null, QualityCaseClass.UNCERTAIN, STOP, QualityCaseGrade.ORDINARY, QualityCaseOrigin.CONTEXA,
                null);
    }

    /** Normal work that is its own root. */
    static QualityCase normal(String key) {
        return normal(key, null);
    }

    static QualityCase normal(String key, String root) {
        return of(key, root, QualityCaseClass.NORMAL, PASS, QualityCaseGrade.ORDINARY, QualityCaseOrigin.CONTEXA, null);
    }

    /** A case that must be caught: only BLOCK is right. */
    static QualityCase mustCatch(String key) {
        return of(key, null, QualityCaseClass.THREAT, EnumSet.of(QualityAction.BLOCK), QualityCaseGrade.MUST_CATCH,
                QualityCaseOrigin.CONTEXA, null);
    }

    /** Normal work that must not be blocked. */
    static QualityCase mustNotBlock(String key) {
        return of(key, null, QualityCaseClass.NORMAL, PASS, QualityCaseGrade.MUST_NOT_BLOCK, QualityCaseOrigin.CONTEXA,
                null);
    }

    static QualityCase of(String key, String root, QualityCaseClass classification, Set<QualityAction> allowed,
                          QualityCaseGrade grade, QualityCaseOrigin origin, Instant addedAt) {
        return new QualityCase(key, input(JSON.createObjectNode()),
                new QualityCaseExpectation(allowed, null, classification,
                        classification == QualityCaseClass.NORMAL ? QualityCaseKind.NORMAL_WORK
                                : QualityCaseKind.OUTSIDER,
                        new QualityCaseRationale(null, "A case of the tests."), List.of()),
                grade, root, new QualityCaseEnvironment("UTC", QualityCaseEnvironment.FIRST_CONTEXT_FORMAT), origin,
                addedAt);
    }

    static QualityCaseInput input(JsonNode canonicalContext) {
        return new QualityCaseInput(canonicalContext, JSON.createObjectNode(), JSON.createObjectNode(),
                JSON.createObjectNode(), JSON.createObjectNode(), null, null, null);
    }

    /**
     * One row of a result file of the local measurement, with the columns the scoring reads. The file kept the case
     * definition with each answer: the kind, the class, the allowed actions and the expected explanation.
     */
    record LocalRow(String caseKey, String kind, String expected, List<String> allowed, String hypothesis, int run,
                    String action, boolean correct, boolean modelLess, boolean retried, int cited, int onALine,
                    int namedByTheCheck, boolean promptHasFactIds, int outputTokens, long elapsedMs) {
    }

    /** The rows of a result file of the local measurement under {@code prompt-quality/local-measurement}. */
    static List<LocalRow> localRows(String file) {
        String resource = "prompt-quality/local-measurement/" + file;
        try (InputStream input = QualityFixtures.class.getClassLoader().getResourceAsStream(resource)) {
            if (input == null) {
                throw new IllegalStateException("The result file is missing: " + resource);
            }
            List<LocalRow> rows = new ArrayList<>();
            BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                if (line.isBlank()) {
                    continue;
                }
                JsonNode row = JSON.readTree(line);
                List<String> allowed = new ArrayList<>();
                row.path("allowed").forEach(action -> allowed.add(action.asText()));
                JsonNode citations = row.path("citations");
                rows.add(new LocalRow(row.path("case").asText(), row.path("kind").asText(),
                        row.path("expected").asText(), allowed, row.path("expectedHypothesis").asText(),
                        row.path("run").asInt(), row.path("action").asText(null), row.path("correct").asBoolean(),
                        row.path("modelLess").asBoolean(), row.path("retried").asBoolean(),
                        citations.path("cited").asInt(), citations.path("onALine").asInt(),
                        citations.path("namedByTheCheck").asInt(), citations.path("promptHasFactIds").asBoolean(),
                        row.path("outputTokens").asInt(), row.path("elapsedMs").asLong()));
            }
            return rows;
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }
}
