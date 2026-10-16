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
package io.contexa.contexacore.autonomous.learning.evidence;

import io.contexa.contexacore.autonomous.baseline.BaselineView;
import io.contexa.contexacore.autonomous.baseline.BaselineViewCalculator;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class LearningContextEvidenceAssemblerTest {

    private final LearningContextEvidenceAssembler assembler = new LearningContextEvidenceAssembler();

    @Test
    @DisplayName("assembler should derive no-data baseline when no typed personal baseline evidence exists")
    void assemblerShouldDeriveNoDataBaselineWithoutTypedEvidence() {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();

        LearningContextEvidence evidence = assembler.assemble(
                "alice",
                SecurityEvent.builder().userId("alice").build(),
                null,
                behaviorAnalysis,
                List.of());

        assertThat(evidence.personalBaseline().status()).isEqualTo(BaselineEvidenceStatus.NO_DATA);
        assertThat(evidence.personalBaseline().summary()).isEmpty();
        assertThat(evidence.personalBaseline().diagnostic()).isEmpty();
        assertThat(evidence.carryRequiredFacts())
                .doesNotContain(
                        "HistoricalComparableScope",
                        "HistoricalComparableCount",
                        "HistoricalComparableSummary",
                        "ComparableExample1",
                        "CurrentRequestClosestObservedOverlap");
    }

    @Test
    @DisplayName("assembler should preserve explicit typed unavailable baseline evidence")
    void assemblerShouldPreserveExplicitTypedUnavailableBaselineEvidence() {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL,
                false,
                false,
                null,
                null,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                "",
                BaselineEvidenceStatus.SERVICE_UNAVAILABLE,
                "baseline service unavailable"));

        LearningContextEvidence evidence = assembler.assemble(
                "alice",
                SecurityEvent.builder().userId("alice").build(),
                null,
                behaviorAnalysis,
                List.of());

        assertThat(evidence.personalBaseline().status()).isEqualTo(BaselineEvidenceStatus.SERVICE_UNAVAILABLE);
        assertThat(evidence.personalBaseline().diagnostic()).isEqualTo("baseline service unavailable");
    }

    @Test
    @DisplayName("a device is new when its browser or operating system is outside the observed ones (W1-10)")
    void deviceOutsideObservedComparesWithTheObservedDevices() {
        assertThat(deviceEvidence("Chrome", "120", "Windows", List.of("Chrome/120"), List.of("Windows"))
                .deviceOutsideObserved()).isFalse();
        assertThat(deviceEvidence("Firefox", "130", "Windows", List.of("Chrome/120"), List.of("Windows"))
                .deviceOutsideObserved()).isTrue();
        assertThat(deviceEvidence("Chrome", "120", "Windows", List.of(), List.of())
                .deviceOutsideObserved()).isNull();
    }

    @Test
    void theDeviceIsOneDimensionComparedByItsLearnedPairs() {
        // W2-4: a new browser on a new system is one delta, not two.
        LearningContextEvidence bothNew = deviceEvidence("Safari", "18", "MAC", List.of("Chrome/120"), List.of("WINDOWS"));
        assertThat(bothNew.currentVsObservedDeltas())
                .extracting(CurrentVsObservedDeltaSnapshot::key)
                .containsOnlyOnce("device")
                .doesNotContain("browser", "operatingSystem");
        assertThat(bothNew.deviceOutsideObserved()).isTrue();

        // A browser and a system each seen before, never together: a new device once the baseline learned pairs.
        LearningContextEvidence newPair = pairedDeviceEvidence("Safari", "18", "Windows",
                List.of("Chrome/120 on WINDOWS", "Safari/18 on MAC"));
        assertThat(newPair.current().device()).isEqualTo("Safari/18 on WINDOWS");
        assertThat(newPair.deviceOutsideObserved()).isTrue();
        assertThat(newPair.currentVsObservedDeltas()).extracting(CurrentVsObservedDeltaSnapshot::description)
                .contains("device outside observed devices");
        assertThat(pairedDeviceEvidence("Safari", "18", "Mac", List.of("Chrome/120 on WINDOWS", "Safari/18 on MAC"))
                .deviceOutsideObserved()).isFalse();
    }

    @Test
    @DisplayName("the current path family is the one the context resolved, so another document is no new path (W2-2)")
    void theCurrentPathFamilyIsTheOneTheContextResolved() {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL, true, true, 20L, 0.91d,
                List.of("CORPORATE"), List.of("10"), List.of("3"), List.of("Chrome/120"), List.of("Windows"),
                List.of("/api/documents/{documentKey}"), List.of("PASSWORD"), List.of("READ"), List.of("NORMAL"),
                "personal baseline established", BaselineEvidenceStatus.AVAILABLE, ""));
        SecurityEvent event = SecurityEvent.builder().userId("alice").sourceIp("10.10.0.20").build();
        event.addMetadata("requestPath", "/api/documents/HX-310-DWG-00002");
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder()
                        .requestPath("/api/documents/HX-310-DWG-00002")
                        .pathFamily("/api/documents/{documentKey}")
                        .build())
                .build();

        LearningContextEvidence evidence = assembler.assemble("alice", event, context, behaviorAnalysis, List.of());

        assertThat(evidence.current().pathFamily()).isEqualTo("/api/documents/{documentKey}");
        assertThat(evidence.currentVsObservedDeltas()).noneMatch(delta -> "pathFamily".equals(delta.key()));
    }

    @Test
    @DisplayName("the current class is the resource's class, never the role scope's category (W2-10)")
    void theCurrentClassIsNeverTheRoleScopesCategory() {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        SecurityEvent event = SecurityEvent.builder().userId("alice").sourceIp("10.10.0.20").build();
        CanonicalSecurityContext categoryOnly = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder()
                        .requestPath("/api/releases/R-1")
                        .resourceCategory("PUBLIC_RELEASES")
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .currentResourceFamily("PUBLIC_RELEASES")
                        .build())
                .build();
        CanonicalSecurityContext classified = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder()
                        .requestPath("/api/releases/R-1")
                        .resourceClass("SENSITIVE")
                        .resourceCategory("PUBLIC_RELEASES")
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .currentResourceFamily("PUBLIC_RELEASES")
                        .build())
                .build();

        // The word PUBLIC in the category's name used to make the request a PUBLIC resource.
        assertThat(assembler.assemble("alice", event, categoryOnly, behaviorAnalysis, List.of())
                .current().resourceFamily()).isNull();
        assertThat(assembler.assemble("alice", event, classified, behaviorAnalysis, List.of())
                .current().resourceFamily()).isEqualTo("SENSITIVE");
    }

    @Test
    @DisplayName("the observed hours are the usual-behaviour view's window and every observed list is sorted (W2-3)")
    void theObservedHoursComeFromTheBaselineViewAndEveryListIsSorted() {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL, true, true, 25L, 0.91d,
                List.of("10.40.12", "10.20.1"), List.of("17", "3", "9"), List.of("5", "1"), List.of("Firefox/130", "Chrome/140"),
                List.of("Windows"), List.of("/api/documents/{documentKey}"), List.of("PASSWORD"), List.of("READ"),
                List.of("NORMAL"), "personal baseline established", BaselineEvidenceStatus.AVAILABLE, ""));
        List<BaselineViewCalculator.Observation> observations = new ArrayList<>();
        long now = LocalDateTime.of(2026, 10, 7, 14, 0).toInstant(ZoneOffset.UTC).toEpochMilli();
        for (int index = 0; index < 12; index++) {
            observations.add(new BaselineViewCalculator.Observation(
                    LocalDateTime.of(2026, 10, 6, index % 2 == 0 ? 10 : 14, index).toInstant(ZoneOffset.UTC).toEpochMilli(),
                    "READ", "protectableMethod", true, "INTERNAL", "/api/documents/{documentKey}",
                    "/api/documents/D-" + index, null, true));
        }
        BaselineView view = BaselineViewCalculator.calculate(observations, now, ZoneOffset.UTC);
        SecurityEvent event = SecurityEvent.builder().userId("alice").sourceIp("10.40.12.20").build();
        event.addMetadata("requestPath", "/api/documents/D-99");
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .workProfile(CanonicalSecurityContext.WorkProfile.builder().baselineView(view).build())
                .build();

        LearningContextEvidence evidence = assembler.assemble("alice", event, context, behaviorAnalysis, List.of());

        // H-9: the baseline remembers 03:00 forever; the view's window says when the subject works now.
        assertThat(evidence.observedPatterns().accessHours()).containsExactly("10", "14");
        // E-1: the same facts read in the same order on every run.
        // W2-4: learned prefixes read as their /24 bands.
        assertThat(evidence.observedPatterns().networks()).containsExactly("10.20.1.0/24", "10.40.12.0/24");
        assertThat(evidence.observedPatterns().browsers()).containsExactly("Chrome/140", "Firefox/130");
        assertThat(evidence.baselineView().state()).isEqualTo(BaselineView.State.ESTABLISHED);
        assertThat(evidence.baselineView().learnedUpdates()).isEqualTo(25L);
        // W5-9: the view's networks are its observations' own, not the long-term baseline's; these observations were
        // stored before W5-9 and hold none.
        assertThat(evidence.baselineView().usualNetworks()).isEmpty();
    }

    private LearningContextEvidence deviceEvidence(
            String browser, String version, String system, List<String> observedBrowsers, List<String> observedSystems) {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL, true, true, 20L, 0.91d,
                List.of("CORPORATE"), List.of("10"), List.of("3"), observedBrowsers, observedSystems,
                List.of("/api/reports/*"), List.of("PASSWORD"), List.of("READ"), List.of("NORMAL"),
                "personal baseline established", BaselineEvidenceStatus.AVAILABLE, ""));
        SecurityEvent event = SecurityEvent.builder().userId("alice").sourceIp("10.10.0.20").build();
        event.addMetadata("requestPath", "/api/reports/r-1");
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .device(CanonicalSecurityContext.Device.builder().browser(browser).browserVersion(version).os(system).build())
                .build();
        return assembler.assemble("alice", event, context, behaviorAnalysis, List.of());
    }

    private LearningContextEvidence pairedDeviceEvidence(
            String browser, String version, String system, List<String> observedDevices) {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL, true, true, 20L, 0.91d,
                List.of("10.10.0.0/24"), List.of("10"), List.of("3"), List.of("Chrome/120", "Safari/18"),
                List.of("MAC", "WINDOWS"), List.of("/api/reports/*"), List.of("PASSWORD"), List.of("READ"),
                List.of("NORMAL"), "personal baseline established", BaselineEvidenceStatus.AVAILABLE, "",
                observedDevices));
        SecurityEvent event = SecurityEvent.builder().userId("alice").sourceIp("10.10.0.20").build();
        event.addMetadata("requestPath", "/api/reports/r-1");
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .device(CanonicalSecurityContext.Device.builder().browser(browser).browserVersion(version).os(system).build())
                .build();
        return assembler.assemble("alice", event, context, behaviorAnalysis, List.of());
    }

    @Test
    @DisplayName("assembler should normalize requested resource ids into comparable path families and combination carry facts")
    void assemblerShouldNormalizeRequestedResourceIdsIntoComparablePathFamilies() {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL,
                true,
                true,
                20L,
                0.91d,
                List.of("CORPORATE"),
                List.of("23"),
                List.of("6"),
                List.of("Chrome/120"),
                List.of("Windows"),
                List.of("/admin/api/security-test/sensitive/*"),
                List.of("PASSWORD"),
                List.of("READ"),
                List.of("SENSITIVE"),
                "personal baseline established",
                BaselineEvidenceStatus.AVAILABLE,
                ""));

        SecurityEvent event = SecurityEvent.builder()
                .userId("alice")
                .sourceIp("10.10.0.20")
                .build();
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/self-sensitive-1");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("deviceBrowser", "Chrome");
        event.addMetadata("deviceBrowserVersion", "120");
        event.addMetadata("deviceOs", "Windows");
        event.addMetadata("authMethod", "UsernamePasswordAuthenticationToken");

        LearningContextEvidence evidence = assembler.assemble(
                "alice",
                event,
                null,
                behaviorAnalysis,
                List.of(new Document(
                        "behavior summary",
                        Map.of(
                                "documentType", "behavior",
                                "userId", "alice",
                                "requestedResourceId", "/admin/api/security-test/sensitive/baseline-3",
                                "resourceSensitivity", "HIGH",
                                "hour", "23",
                                "dayOfWeek", "6",
                                "deviceBrowser", "Chrome/120",
                                "deviceOs", "Windows",
                                "authenticationType", "PASSWORD",
                                "actionFamily", "READ"))));

        assertThat(evidence.personalRetrievedEvidence()).hasSize(1);
        assertThat(evidence.personalRetrievedEvidence().get(0).pathFamily())
                .isEqualTo("/admin/api/security-test/sensitive/*");
        assertThat(evidence.carryRequiredFacts())
                .contains(
                        "WorkProfileEvidenceState",
                        "ObservedPatternEvidenceScope",
                        "HistoricalComparableScope",
                        "CurrentRequestCombinationEvidenceScope",
                        "CurrentRequestCombinationSeenCount",
                        "CurrentRequestCombinationComparedDimensions",
                        "CurrentRequestClosestObservedOverlap",
                        "StrongestCurrentRequestCombinationDelta",
                        "CurrentRequestCombinationSummary",
                        "ObservedComparableCombination1");
    }

    @Test
    @DisplayName("past records of equal similarity keep one order: the document ID breaks the tie (W3-3)")
    void pastRecordsOfEqualSimilarityAreOrderedByTheirDocumentId() {
        SecurityEvent event = SecurityEvent.builder().userId("alice").sourceIp("10.10.0.20").build();
        List<Document> documents = List.of(record("event-3"), record("event-1"), record("event-2"));

        LearningContextEvidence evidence = assembler.assemble("alice", event, null,
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(), documents);
        LearningContextEvidence turned = assembler.assemble("alice", event, null,
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(), List.of(record("event-2"), record("event-1"), record("event-3")));

        assertThat(evidence.personalRetrievedEvidence()).extracting(RetrievedBehaviorEvidence::artifactId)
                .containsExactly("event-1", "event-2", "event-3");
        assertThat(turned.personalRetrievedEvidence()).extracting(RetrievedBehaviorEvidence::artifactId)
                .containsExactly("event-1", "event-2", "event-3");
    }

    private static Document record(String eventId) {
        return Document.builder()
                .id("doc-" + eventId)
                .text("behavior summary " + eventId)
                .metadata(Map.of("documentType", "behavior", "userId", "alice", "eventId", eventId,
                        "requestPath", "/api/documents/D-1", "actionFamily", "READ"))
                .score(0.75)
                .build();
    }
}
