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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * One labelled case as a JSON document (plan 3.2), in the form a case of a case set document has: its key, root,
 * grade, input, right answer and environment. Where it comes from and when it came in are kept beside the document,
 * not in it, as they are no content of the case. A case written and read again has the same content hash.
 */
public final class QualityCaseDocuments {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private QualityCaseDocuments() {
    }

    /** The document of the case. */
    public static ObjectNode write(QualityCase item) {
        ObjectNode document = NODES.objectNode();
        document.put("key", item.key());
        document.put("rootCaseKey", item.rootCaseKey());
        document.put("grade", item.grade().name());
        document.set("expectation", writeExpectation(item.expectation()));
        document.set("environment", writeEnvironment(item.environment()));
        document.set("input", writeInput(item.input()));
        return document;
    }

    /** The decision input of a case as a document. */
    public static ObjectNode writeInput(QualityCaseInput input) {
        ObjectNode document = NODES.objectNode();
        document.set("canonicalContext", input.canonicalContext());
        document.set("requestFacts", input.requestFacts());
        document.set("authState", input.authState());
        document.set("baselineSnapshot", input.baselineSnapshot());
        document.set("ragResults", input.ragResults());
        document.set("pastDeniedDecisions", orNull(input.pastDeniedDecisions()));
        document.set("personalBaseline", orNull(input.personalBaseline()));
        document.set("organizationBaseline", orNull(input.organizationBaseline()));
        return document;
    }

    /** The right answer of a case as a document. */
    public static ObjectNode writeExpectation(QualityCaseExpectation expectation) {
        ObjectNode document = NODES.objectNode();
        ArrayNode allowed = document.putArray("allowedActions");
        expectation.allowedActions().forEach(action -> allowed.add(action.name()));
        document.put("preferredAction", expectation.preferredAction() != null
                ? expectation.preferredAction().name() : null);
        document.put("classification", expectation.classification().name());
        document.put("kind", expectation.kind().name());
        ObjectNode rationale = document.putObject("rationale");
        rationale.put("ko", expectation.rationale().korean());
        rationale.put("en", expectation.rationale().english());
        ArrayNode facts = document.putArray("decidingFacts");
        expectation.decidingFacts().forEach(facts::add);
        return document;
    }

    /** The environment a case fixes as a document. */
    public static ObjectNode writeEnvironment(QualityCaseEnvironment environment) {
        ObjectNode document = NODES.objectNode();
        document.put("timeZone", environment.timeZone());
        document.put("contextFormatVersion", environment.contextFormatVersion());
        return document;
    }

    /**
     * The case of the document, marked as coming from the origin and as having come in at the time.
     *
     * @param addedAt when the case came in, or null when that is not recorded; the document's own {@code addedAt} is
     *                read when this is null
     * @throws IllegalArgumentException when the document is no case
     */
    public static QualityCase read(JsonNode document, QualityCaseOrigin origin, Instant addedAt) {
        String key = document != null ? text(document, "key") : null;
        try {
            String written = text(document, "addedAt");
            return new QualityCase(key, readInput(document.path("input")), readExpectation(document.path("expectation")),
                    QualityCaseGrade.valueOf(document.path("grade").asText()), text(document, "rootCaseKey"),
                    readEnvironment(document.path("environment")), origin,
                    addedAt != null ? addedAt : written != null ? Instant.parse(written) : null);
        }
        catch (RuntimeException exception) {
            throw new IllegalArgumentException("The case " + key + " of the document cannot be read: "
                    + exception.getMessage(), exception);
        }
    }

    /** The decision input of the document. */
    public static QualityCaseInput readInput(JsonNode input) {
        return new QualityCaseInput(input.get("canonicalContext"), input.get("requestFacts"), input.get("authState"),
                input.get("baselineSnapshot"), input.get("ragResults"), input.get("pastDeniedDecisions"),
                input.get("personalBaseline"), input.get("organizationBaseline"));
    }

    /** The right answer of the document. */
    public static QualityCaseExpectation readExpectation(JsonNode expectation) {
        Set<QualityAction> allowed = EnumSet.noneOf(QualityAction.class);
        for (JsonNode action : expectation.path("allowedActions")) {
            allowed.add(QualityAction.valueOf(action.asText()));
        }
        List<String> decidingFacts = new ArrayList<>();
        expectation.path("decidingFacts").forEach(fact -> decidingFacts.add(fact.asText()));
        String preferred = text(expectation, "preferredAction");
        return new QualityCaseExpectation(allowed, preferred != null ? QualityAction.valueOf(preferred) : null,
                QualityCaseClass.valueOf(expectation.path("classification").asText()),
                QualityCaseKind.valueOf(expectation.path("kind").asText()),
                new QualityCaseRationale(text(expectation.path("rationale"), "ko"),
                        text(expectation.path("rationale"), "en")),
                decidingFacts);
    }

    /** The environment of the document. */
    public static QualityCaseEnvironment readEnvironment(JsonNode environment) {
        return new QualityCaseEnvironment(text(environment, "timeZone"), text(environment, "contextFormatVersion"));
    }

    private static JsonNode orNull(JsonNode node) {
        return node != null ? node : NODES.nullNode();
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isMissingNode() || value.isNull() ? null : value.asText();
    }
}
