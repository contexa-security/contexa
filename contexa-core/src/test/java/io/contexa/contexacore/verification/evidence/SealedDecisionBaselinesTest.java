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
package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.baseline.DecisionBaselines;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.config.ApplicationConfig;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayInputs;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.GZIPInputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A sealed package keeps the baselines its decision read, under one key of the baseline snapshot its hash has always
 * covered: the values as they were read; that there was none, told from a package that kept none; and a package
 * sealed before the baselines were reads, verifies and is restored for a replay as it always was.
 */
class SealedDecisionBaselinesTest {

    /** The mapper the product seals and reads packages with. */
    private static final ObjectMapper JSON = new ApplicationConfig().objectMapper();
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };
    private static final String GOLDEN = "prompt-bundles/golden/cortex.security-decision/case-inputs.json.gz";

    private final SealedEvidencePromptTraceStore traceStore = new SealedEvidencePromptTraceStore();
    private final SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity();
    private final SealedEvidencePackageAssembler assembler = new SealedEvidencePackageAssembler(
            JSON, new CanonicalSecurityContextSerializer(JSON), integrity, traceStore);

    @Test
    void theBaselinesTheDecisionReadAreSealedAsTheyWereRead() throws Exception {
        BaselineVector personal = personal();
        BaselineVector organization = organization();
        DecisionBaselines read = DecisionBaselines.readNow(personal, organization);
        // The decision is enforced and learned from before the capture assembles its package.
        personal.getNormalIpRanges()[0] = "203.0.113.0/24";
        personal.setUpdateCount(26L);

        SealedEvidencePackage sealed = seal("req-read", read);

        Optional<DecisionBaselines> kept = SealedDecisionBaselines.read(sealed, JSON);
        assertThat(kept).isPresent();
        assertThat(kept.get().personal()).isEqualTo(read.personal());
        assertThat(kept.get().personal().getNormalIpRanges()).containsExactly("10.1.0.0/16");
        assertThat(kept.get().personal().getUpdateCount()).isEqualTo(25L);
        assertThat(kept.get().personal().getLastUpdated()).isEqualTo(Instant.parse("2026-11-21T08:00:00Z"));
        assertThat(kept.get().organization()).isEqualTo(read.organization());
        // The values the section always kept are sealed beside them.
        assertThat(JSON.readValue(sealed.getBaselineSnapshotJson(), MAP))
                .containsEntry("baselineEstablished", true).containsKey(SealedDecisionBaselines.KEY);
    }

    /** The key is inside a section the hash covers: the schema is as it was, and a changed baseline is a changed package. */
    @Test
    void theSealedBaselinesAreCoveredByThePackageHashOfTheSameSchema() {
        SealedEvidencePackage sealed = seal("req-hash", DecisionBaselines.readNow(personal(), null));

        assertThat(sealed.getSchemaVersion()).isEqualTo(2);
        assertThat(integrity.evaluate(sealed)).isEqualTo(SealedEvidencePackageIntegrity.Status.VERIFIED);

        sealed.setBaselineSnapshotJson(sealed.getBaselineSnapshotJson().replace("10.1.0.0/16", "198.51.100.0/24"));
        assertThat(integrity.evaluate(sealed)).isEqualTo(SealedEvidencePackageIntegrity.Status.MISMATCH);
    }

    @Test
    void aDecisionThatFoundNoBaselineSealsThatThereWasNone() throws Exception {
        SealedEvidencePackage sealed = seal("req-none", DecisionBaselines.readNow(null, null));

        JsonNode key = JSON.readTree(sealed.getBaselineSnapshotJson()).get(SealedDecisionBaselines.KEY);
        assertThat(key).as("the key is sealed").isNotNull();
        assertThat(key.get("personal").isNull()).isTrue();
        assertThat(key.get("organization").isNull()).isTrue();
        Optional<DecisionBaselines> kept = SealedDecisionBaselines.read(sealed, JSON);
        assertThat(kept).as("sealed, and none").isPresent();
        assertThat(kept.get().personal()).isNull();
        assertThat(kept.get().organization()).isNull();
    }

    /** One of the two may be there without the other: a new member of an organization that has a baseline. */
    @Test
    void aBaselineThatWasThereIsSealedBesideOneThatWasNot() {
        SealedEvidencePackage sealed = seal("req-org-only", DecisionBaselines.readNow(null, organization()));

        DecisionBaselines kept = SealedDecisionBaselines.read(sealed, JSON).orElseThrow();
        assertThat(kept.personal()).isNull();
        assertThat(kept.organization().getNormalOperatingSystems()).containsExactly("WINDOWS");
    }

    /**
     * A decision whose analysis kept no baselines (none could be read) seals the section byte for byte as before, and
     * the package says nothing about the baselines.
     */
    @Test
    void aDecisionThatKeptNoBaselinesSealsTheSectionAsBefore() {
        SealedEvidencePackage sealed = seal("req-not-kept", null);

        assertThat(sealed.getBaselineSnapshotJson()).isEqualTo("{\"baselineEstablished\":true}");
        assertThat(SealedDecisionBaselines.read(sealed, JSON)).isEmpty();
    }

    /**
     * A package sealed before the baselines were: its hash, computed apart from this code over the fields the hash has
     * always covered, still verifies, and it reads as a package that kept no baselines.
     */
    @Test
    void aPackageSealedBeforeTheBaselinesKeepsItsHashAndItsState() {
        SealedEvidencePackage earlier = earlierPackage();
        earlier.setPackageHash("33bbb908cf3ace0096626ced8cdc215ae37cd0780f2fc6281e7a74e44bf223ae");

        assertThat(integrity.computeHash(earlier)).isEqualTo(earlier.getPackageHash());
        assertThat(integrity.evaluate(earlier)).isEqualTo(SealedEvidencePackageIntegrity.Status.VERIFIED);
        assertThat(SealedDecisionBaselines.read(earlier, JSON)).isEmpty();
        assertThat(SealedDecisionBaselines.read(new SealedEvidencePackage(), JSON)).isEmpty();
    }

    /**
     * A replay restores the section as the request's metadata, as it always did, without the baselines: they are the
     * replay's baselines, not a fact of the request.
     */
    @Test
    void aReplayRestoresTheSectionAsRequestMetadataWithoutTheBaselines() {
        SealedEvidencePackage earlier = earlierPackage();
        SealedEvidencePackage withBaselines = earlierPackage();
        ObjectNode snapshot = (ObjectNode) read(withBaselines.getBaselineSnapshotJson());
        snapshot.set(SealedDecisionBaselines.KEY,
                SealedDecisionBaselines.write(DecisionBaselines.readNow(personal(), organization()), JSON));
        withBaselines.setBaselineSnapshotJson(snapshot.toString());

        Map<String, Object> before = restored(earlier);
        Map<String, Object> after = restored(withBaselines);

        assertThat(before).containsEntry("baselineEstablished", true).containsEntry("personalBaselineEstablished", true)
                .containsEntry("isNewUser", false).doesNotContainKey(SealedDecisionBaselines.KEY);
        assertThat(after).as("the same metadata with and without the sealed baselines").isEqualTo(before);
    }

    @Test
    void sealedBaselinesThatCannotBeReadAreRefusedNotReplaced() {
        SealedEvidencePackage broken = earlierPackage();
        broken.setBaselineSnapshotJson("{\"decisionBaselines\":{\"personal\":{\"updateCount\":\"many\"}}}");

        assertThatThrownBy(() -> SealedDecisionBaselines.read(broken, JSON))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("pkg-earlier");
    }

    /**
     * What the baselines add to a package, on the golden inputs (real and controlled decisions): the bytes of the key
     * in the baseline snapshot as the product's mapper writes it. The numbers are written to the build reports.
     */
    @Test
    void theBaselinesAddAFewKilobytesToAPackage() throws Exception {
        List<Integer> added = new ArrayList<>();
        List<String> lines = new ArrayList<>();
        for (JsonNode goldenCase : goldenCases()) {
            JsonNode learning = goldenCase.path("learningEvidence");
            DecisionBaselines read = new DecisionBaselines(vector(learning.path("personalBaseline")),
                    vector(learning.path("organizationBaseline")));
            ObjectNode before = (ObjectNode) goldenCase.path("baselineSnapshot").deepCopy();
            ObjectNode after = before.deepCopy();
            after.set(SealedDecisionBaselines.KEY, SealedDecisionBaselines.write(read, JSON));
            int bytes = bytes(JSON.writeValueAsString(after)) - bytes(JSON.writeValueAsString(before));
            added.add(bytes);
            lines.add(goldenCase.path("caseKey").asText() + " personal=" + (read.personal() != null)
                    + " organization=" + (read.organization() != null) + " addedBytes=" + bytes);
        }
        List<Integer> sorted = added.stream().sorted().toList();
        long total = added.stream().mapToLong(Integer::longValue).sum();
        lines.add(0, "cases=" + added.size() + " min=" + sorted.get(0) + " median=" + sorted.get(sorted.size() / 2)
                + " max=" + sorted.get(sorted.size() - 1) + " mean=" + Math.round((double) total / added.size())
                + " total=" + total);
        Path report = Path.of("build/reports/sealed-evidence/decision-baselines-size.txt");
        Files.createDirectories(report.getParent());
        Files.write(report, lines, StandardCharsets.UTF_8);

        assertThat(added).isNotEmpty().allMatch(bytes -> bytes > 0);
        assertThat(sorted.get(sorted.size() - 1)).as("the most a golden decision's baselines add").isLessThan(16 * 1024);
    }

    private Map<String, Object> restored(SealedEvidencePackage sealed) {
        // The replay's own ids are the same for both packages here; the sealed sections are what is compared.
        SecurityEvent event = SealedDecisionReplayInputs.of(sealed, "replay-test", JSON,
                new CanonicalSecurityContextSerializer(JSON)).event();
        return new HashMap<>(event.getMetadata());
    }

    private static JsonNode read(String json) {
        try {
            return JSON.readTree(json);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static int bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8).length;
    }

    private static BaselineVector vector(JsonNode node) {
        return node.isMissingNode() || node.isNull() ? null : JSON.convertValue(node, BaselineVector.class);
    }

    private static List<JsonNode> goldenCases() throws IOException {
        try (InputStream input = SealedDecisionBaselinesTest.class.getClassLoader().getResourceAsStream(GOLDEN)) {
            assertThat(input).as(GOLDEN).isNotNull();
            List<JsonNode> cases = new ArrayList<>();
            try (GZIPInputStream gzip = new GZIPInputStream(input)) {
                JSON.readTree(gzip.readAllBytes()).path("cases").forEach(cases::add);
            }
            return cases;
        }
    }

    /** A schema 2 package as an earlier build sealed it: every field fixed, its baseline snapshot without the key. */
    private static SealedEvidencePackage earlierPackage() {
        return SealedEvidencePackage.builder()
                .packageId("pkg-earlier")
                .correlationId("req-earlier")
                .capturedAt(Instant.parse("2026-11-01T05:00:00Z"))
                .requestFactsJson("{\"requestId\":\"req-earlier\",\"userId\":\"alice\"}")
                .authStateJson("{\"authMethod\":\"password\"}")
                .canonicalContextJson("{}")
                .baselineSnapshotJson("{\"baselineEstablished\":true,\"personalBaselineEstablished\":true,"
                        + "\"isNewUser\":false}")
                .ragResultsJson("{\"ragRetrievalState\":\"RETRIEVED\"}")
                .rawSystemPrompt("system")
                .rawUserPrompt("user")
                .systemPromptText("system")
                .userPromptText("user")
                .systemPromptHash("sha256:s")
                .userPromptHash("sha256:u")
                .rawSystemPromptHash("sha256:s")
                .rawUserPromptHash("sha256:u")
                .sealState("SEALED")
                .promptExecutionMetadataJson("{\"promptVersion\":\"v1.0\"}")
                .decisionJson("{\"action\":\"ALLOW\"}")
                .schemaVersion(2)
                .build();
    }

    private SealedEvidencePackage seal(String requestId, DecisionBaselines read) {
        SecurityEvent event = SecurityEvent.builder().eventId("evt-" + requestId).userId("alice").sessionId("s-1").build();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("requestId", requestId);
        metadata.put("requestPath", "/api/orders/1");
        metadata.put("baselineEstablished", true);
        event.setMetadata(metadata);

        PromptGenerationResult promptResult = mock(PromptGenerationResult.class);
        when(promptResult.getSystemPrompt()).thenReturn("system prompt");
        when(promptResult.getUserPrompt()).thenReturn("user prompt");
        when(promptResult.getRawSystemPrompt()).thenReturn("system prompt");
        when(promptResult.getRawUserPrompt()).thenReturn("user prompt");
        when(promptResult.getMetadata()).thenReturn(Map.of());
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        analysis.setDecisionBaselines(read);
        SecurityDecisionContext capture = mock(SecurityDecisionContext.class);
        when(capture.getSecurityEvent()).thenReturn(event);
        when(capture.getRelatedDocuments()).thenReturn(List.of());
        when(capture.getBehaviorAnalysis()).thenReturn(analysis);
        traceStore.capture(capture, promptResult);
        traceStore.complete(event);

        SecurityEventContext context = new SecurityEventContext(event);
        ProcessingResult result = ProcessingResult.builder().success(true).build();
        result.setAction("ALLOW");
        context.addMetadata("processingResult", result);
        SealedEvidencePackage sealed = assembler.assemble(context);
        assertThat(sealed).isNotNull();
        return sealed;
    }

    private static BaselineVector personal() {
        return BaselineVector.builder()
                .userId("tenant-a::alice")
                .normalIpRanges(new String[]{"10.1.0.0/16"})
                .normalAccessHours(new Integer[]{9, 10})
                .normalDevices(new String[]{"Chrome/140 on WINDOWS"})
                .updateCount(25L)
                .elementFrequencies(new HashMap<>(Map.of("ip:10.1.0.0/16", 25L)))
                .elementLastSeen(new HashMap<>(Map.of("ip:10.1.0.0/16", 1_795_000_000_000L)))
                .verifiedElements(new HashSet<>(List.of("ip:10.1.0.0/16")))
                .lastUpdated(Instant.parse("2026-11-21T08:00:00Z"))
                .avgTrustScore(0.8d)
                .build();
    }

    private static BaselineVector organization() {
        return BaselineVector.builder()
                .userId("org:org-a")
                .normalOperatingSystems(new String[]{"WINDOWS"})
                .updateCount(400L)
                .learnedMembers(new HashSet<>(List.of("member-1", "member-2")))
                .build();
    }
}
