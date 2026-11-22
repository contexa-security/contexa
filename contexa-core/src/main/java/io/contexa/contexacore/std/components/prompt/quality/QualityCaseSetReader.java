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

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * Reads a set of labelled cases from its document (plan 3.2), and the default set Contexa ships as a product resource.
 * The document is JSON: the name of the set and its cases, each a finished case with its whole input.
 */
public final class QualityCaseSetReader {

    /** The default set of the security decision prompt: the 60 cases and the 10 control cases, compressed. */
    public static final String CONTEXA_DEFAULT_RESOURCE =
            "prompt-quality/cortex.security-decision/contexa-default-cases.json.gz";

    /** The version of the form of the document this reader reads. */
    public static final int DOCUMENT_FORMAT = 1;

    private static final ObjectMapper JSON = new ObjectMapper();

    private QualityCaseSetReader() {
    }

    /** The default set Contexa ships. It is read from the resource on each call; the caller keeps what it needs. */
    public static QualityCaseSet contexaDefault() {
        try (InputStream resource = QualityCaseSetReader.class.getClassLoader()
                .getResourceAsStream(CONTEXA_DEFAULT_RESOURCE)) {
            if (resource == null) {
                throw new IllegalStateException("The default case set is missing: " + CONTEXA_DEFAULT_RESOURCE);
            }
            try (GZIPInputStream json = new GZIPInputStream(resource)) {
                return read(json, QualityCaseOrigin.CONTEXA);
            }
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    /** The set of the JSON document, its cases marked as coming from the origin. */
    public static QualityCaseSet read(InputStream json, QualityCaseOrigin origin) throws IOException {
        return read(JSON.readTree(json), origin);
    }

    /** The set of the document, its cases marked as coming from the origin. */
    public static QualityCaseSet read(JsonNode document, QualityCaseOrigin origin) {
        if (document == null || document.path("format").asInt(-1) != DOCUMENT_FORMAT) {
            throw new IllegalArgumentException("The case set document is not of format " + DOCUMENT_FORMAT);
        }
        List<QualityCase> cases = new ArrayList<>();
        for (JsonNode item : document.path("cases")) {
            cases.add(readCase(item, origin));
        }
        return new QualityCaseSet(document.path("name").asText(null), cases);
    }

    private static QualityCase readCase(JsonNode item, QualityCaseOrigin origin) {
        String key = item.path("key").asText(null);
        try {
            JsonNode input = item.path("input");
            JsonNode expectation = item.path("expectation");
            JsonNode environment = item.path("environment");
            Set<QualityAction> allowed = EnumSet.noneOf(QualityAction.class);
            for (JsonNode action : expectation.path("allowedActions")) {
                allowed.add(QualityAction.valueOf(action.asText()));
            }
            List<String> decidingFacts = new ArrayList<>();
            expectation.path("decidingFacts").forEach(fact -> decidingFacts.add(fact.asText()));
            String preferred = text(expectation, "preferredAction");
            String addedAt = text(item, "addedAt");
            return new QualityCase(key,
                    new QualityCaseInput(input.get("canonicalContext"), input.get("requestFacts"),
                            input.get("authState"), input.get("baselineSnapshot"), input.get("ragResults"),
                            input.get("pastDeniedDecisions"), input.get("personalBaseline"),
                            input.get("organizationBaseline")),
                    new QualityCaseExpectation(allowed, preferred != null ? QualityAction.valueOf(preferred) : null,
                            QualityCaseClass.valueOf(expectation.path("classification").asText()),
                            QualityCaseKind.valueOf(expectation.path("kind").asText()),
                            new QualityCaseRationale(text(expectation.path("rationale"), "ko"),
                                    text(expectation.path("rationale"), "en")),
                            decidingFacts),
                    QualityCaseGrade.valueOf(item.path("grade").asText()),
                    text(item, "rootCaseKey"),
                    new QualityCaseEnvironment(text(environment, "timeZone"),
                            text(environment, "contextFormatVersion")),
                    origin,
                    addedAt != null ? Instant.parse(addedAt) : null);
        }
        catch (RuntimeException exception) {
            throw new IllegalArgumentException("The case " + key + " of the document cannot be read: "
                    + exception.getMessage(), exception);
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isMissingNode() || value.isNull() ? null : value.asText();
    }
}
