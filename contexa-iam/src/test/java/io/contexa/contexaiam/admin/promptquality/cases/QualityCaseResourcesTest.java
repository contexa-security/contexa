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
package io.contexa.contexaiam.admin.promptquality.cases;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.monitoring.ai.DecisionConsoleColumns;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseResource;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexacore.std.components.prompt.quality.QualityResourceCoverage;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Quality P46: the resource class of a case is the one the decision row of the same input gets. Each input is read
 * two ways: as the decision writer reads it (the canonical context restored as the replay restores it, the request's
 * facts as its metadata, the console columns of the decision row) and as the cases read it; the two classes are the
 * same for every case of the default set and for the inputs that take the other branches of the rule.
 */
class QualityCaseResourcesTest {

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    private static final CanonicalSecurityContextSerializer CONTEXTS = new CanonicalSecurityContextSerializer(JSON);

    /** The class of the decision row the writer makes of the input. */
    private static String classOfTheDecisionRow(QualityCaseInput input) {
        CanonicalSecurityContext context = CONTEXTS.deserialize(input.canonicalContext().toString());
        assertThat(context).as("the canonical context is restored").isNotNull();
        Map<String, Object> metadata = new HashMap<>(JSON.convertValue(input.requestFacts(),
                new TypeReference<Map<String, Object>>() {
                }));
        metadata.put("sealedEvidence.canonicalContext", context);
        return DecisionConsoleColumns.of(metadata, null, ZeroTrustAction.ALLOW, Instant.now()).resourceClass();
    }

    private static QualityCaseInput input(ObjectNode resource, ObjectNode facts) {
        ObjectNode context = JSON.createObjectNode();
        context.set("resource", resource);
        return new QualityCaseInput(context, facts, JSON.createObjectNode(), JSON.createObjectNode(),
                JSON.createObjectNode(), null, null, null);
    }

    @Test
    void everyCaseOfTheDefaultSetHasTheClassOfItsDecisionRow() {
        QualityCaseSet shipped = QualityCaseSetReader.contexaDefault();

        Map<String, Integer> byClass = new TreeMap<>();
        Set<String> named = new TreeSet<>();
        for (QualityCase item : shipped.cases()) {
            QualityCaseResource resource = QualityCaseResources.of(item);
            assertThat(resource.resourceClass()).as(item.key()).isEqualTo(classOfTheDecisionRow(item.input()));
            byClass.merge(resource.group(), 1, Integer::sum);
            named.add(resource.resource());
            assertThat(resource.resource()).as(item.key())
                    .isEqualTo(item.input().requestFacts().path("resourceId").asText());
            assertThat(resource.httpMethod()).as(item.key()).isIn("GET", "POST");
            assertThat(resource.urlTemplate()).as(item.key()).startsWith("/api/");
        }

        assertThat(shipped.cases()).hasSize(70);
        assertThat(byClass).containsExactly(Map.entry("CRITICAL", 31), Map.entry("SENSITIVE", 39));
        assertThat(named).hasSize(6);
        // By class and side, with no decision of the operation: nothing is a gap.
        QualityResourceCoverage coverage = QualityResourceCoverage.of(shipped.cases(), QualityCaseResources::of,
                Map.of(), QualityCaseResources.CLASSES, 5, 10);
        assertThat(coverage.classes()).containsExactly(
                new QualityResourceCoverage.ClassRow("CRITICAL", 31, 22, 9, 12, 5, 4, 0, QualityResourceCoverage.Gap.NONE),
                new QualityResourceCoverage.ClassRow("SENSITIVE", 39, 33, 6, 13, 5, 3, 0,
                        QualityResourceCoverage.Gap.NONE),
                new QualityResourceCoverage.ClassRow("NORMAL", 0, 0, 0, 0, 0, 0, 0, QualityResourceCoverage.Gap.NONE),
                new QualityResourceCoverage.ClassRow("PUBLIC", 0, 0, 0, 0, 0, 0, 0, QualityResourceCoverage.Gap.NONE));
        assertThat(coverage.resources()).isEqualTo(6);
        assertThat(coverage.unidentifiedCases()).isZero();
        assertThat(coverage.topResources()).extracting(row -> row.resource().substring(row.resource().indexOf('#') + 1)
                + "=" + row.cases()).containsExactly("readDocument=32", "exportDocuments=19", "readCustomer=8",
                "grantRole=5", "openExportStream=5", "downloadDocument=1");
        assertThat(coverage.topResources().get(0).resourceClasses()).containsExactly("CRITICAL", "SENSITIVE");
        assertThat(coverage.topResources().get(0).urlTemplate()).isEqualTo("/api/documents/{documentKey}");
        assertThat(List.of(coverage.topResources().get(1).httpMethod(), coverage.topResources().get(1).urlTemplate()))
                .containsExactly("POST", "/api/projects/{projectKey}/exports");
    }

    @Test
    void theOtherBranchesOfTheRuleGiveTheSameClassBothWays() {
        ObjectNode none = JSON.createObjectNode();
        ObjectNode flagged = JSON.createObjectNode().put("isSensitiveResource", true);
        ObjectNode flaggedAsText = JSON.createObjectNode().put("isSensitiveResource", "true");
        ObjectNode notFlagged = JSON.createObjectNode().put("isSensitiveResource", false);
        ObjectNode lowerCase = JSON.createObjectNode().put("resourceClass", "critical");
        ObjectNode publicClass = JSON.createObjectNode().put("resourceClass", "PUBLIC");

        Map<String, QualityCaseInput> inputs = Map.of(
                "no class, no mark", input(none, JSON.createObjectNode()),
                "marked sensitive", input(none, flagged),
                "marked sensitive in text", input(none, flaggedAsText),
                "marked not sensitive", input(none, notFlagged),
                "a class in lower case", input(lowerCase, flagged),
                "a public class with the mark", input(publicClass, flagged));
        Map<String, String> expected = Map.of(
                "no class, no mark", "-",
                "marked sensitive", "SENSITIVE",
                "marked sensitive in text", "SENSITIVE",
                "marked not sensitive", "-",
                "a class in lower case", "CRITICAL",
                "a public class with the mark", "PUBLIC");
        inputs.forEach((name, input) -> {
            String ofTheCase = QualityCaseResources.of(input).resourceClass();
            assertThat(ofTheCase).as(name).isEqualTo(classOfTheDecisionRow(input));
            assertThat(ofTheCase == null ? "-" : ofTheCase).as(name).isEqualTo(expected.get(name));
        });
        assertThat(QualityCaseResources.of(input(none, JSON.createObjectNode())))
                .isEqualTo(QualityCaseResource.NONE);
    }

    @Test
    void theResourceIsTheOneTheDecisionRowKeepsElseTheDeclaredOne() {
        ObjectNode both = JSON.createObjectNode().put("resourceId", "Ops#read")
                .put("protectableResourceId", "Ops#declared").put("protectableHttpMethod", "POST")
                .put("httpMethod", "GET").put("protectableResourceUrl", "/api/things/{key}");
        ObjectNode declaredOnly = JSON.createObjectNode().put("protectableResourceId", "Ops#declared")
                .put("httpMethod", "GET");

        assertThat(QualityCaseResources.of(input(JSON.createObjectNode(), both)))
                .isEqualTo(new QualityCaseResource(null, "Ops#read", "POST", "/api/things/{key}"));
        assertThat(QualityCaseResources.of(input(JSON.createObjectNode(), declaredOnly)))
                .isEqualTo(new QualityCaseResource(null, "Ops#declared", "GET", null));
    }

    @Test
    void theClassesShownAndTheClassesOfTheHoursAreThoseOfTheVocabulary() {
        for (String shown : QualityCaseResources.CLASSES) {
            assertThat(SecuritySemanticNormalizer.normalizeResourceClass(shown)).isEqualTo(shown);
        }
        assertThat(QualityCaseResources.groupOfDecisions("")).isEqualTo(QualityCaseResource.UNCLASSIFIED);
        assertThat(QualityCaseResources.groupOfDecisions(null)).isEqualTo(QualityCaseResource.UNCLASSIFIED);
        assertThat(QualityCaseResources.groupOfDecisions("SENSITIVE")).isEqualTo("SENSITIVE");
        assertThat(QualityCaseResources.groupOfDecisions("UNKNOWN")).isEqualTo("UNKNOWN");
    }
}
