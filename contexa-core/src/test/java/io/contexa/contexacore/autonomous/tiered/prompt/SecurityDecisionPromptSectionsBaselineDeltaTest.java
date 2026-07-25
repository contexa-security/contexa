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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.CurrentLearningContextSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.CurrentVsObservedDeltaSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacore.autonomous.learning.evidence.ObservedPatternSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.RetrievedBehaviorEvidence;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionPromptSectionsBaselineDeltaTest {

    @Test
    @DisplayName("buildUserProfileNarrative should expose current-vs-observed baseline deltas")
    void buildUserProfileNarrativeShouldExposeCurrentVsObservedDeltas() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-baseline-delta-001")
                .timestamp(LocalDateTime.of(2026, 4, 18, 16, 4))
                .userId("persona_fin_lead")
                .sessionId("session-baseline-delta")
                .sourceIp("10.10.0.20")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .description("GET /admin/api/security-test/sensitive/self-sensitive-001")
                .build();
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/self-sensitive-001");
        event.addMetadata("currentAccessHour", 16);
        event.addMetadata("deviceBrowser", "Chrome");
        event.addMetadata("deviceBrowserVersion", "120");
        event.addMetadata("deviceOs", "Windows");

        SecurityDecisionStandardPromptTemplate.DetectedPatterns patterns = new SecurityDecisionStandardPromptTemplate.DetectedPatterns();
        patterns.hourSet.add("8");
        patterns.hourSet.add("9");
        patterns.hourSet.add("10");
        patterns.daySet.add("6");
        patterns.ipSet.add("10.10.0.20");
        patterns.uaSet.add("Chrome/120");
        patterns.osSet.add("Windows");
        patterns.pathSet.add("/admin/api/*");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineUpdateCount(20L);
        behaviorAnalysis.setLearningContextEvidence(new LearningContextEvidence(
                new CurrentLearningContextSnapshot("16", "6", "10.10.0.20", "Chrome/120", "Windows", "/admin/api/*", "PASSWORD", "READ", "SENSITIVE"),
                new BaselineEvidenceSnapshot(LearningEvidenceScope.PERSONAL, true, true, 20L, 0.92,
                        List.of("10.10.0.20"), List.of("8", "9", "10"), List.of("6"), List.of("Chrome/120"), List.of("Windows"),
                        List.of("/admin/api/*"), List.of("PASSWORD"), List.of("READ"), List.of("SENSITIVE"),
                        "Personal office baseline established."),
                new BaselineEvidenceSnapshot(LearningEvidenceScope.SUPPORTING, false, false, 0L, null,
                        List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), ""),
                List.of(new RetrievedBehaviorEvidence(
                        LearningEvidenceScope.PERSONAL,
                        "persona_fin_lead",
                        "behavior",
                        "artifact-1",
                        0.95,
                        "10.10.0.20",
                        "10.10.0.20",
                        "/admin/api/security-test/sensitive/self-sensitive-001",
                        "/admin/api/*",
                        "10",
                        "6",
                        "Chrome/120",
                        "Windows",
                        "PASSWORD",
                        "READ",
                        "SENSITIVE",
                        "HIGH",
                        "FINANCE",
                        "12",
                        "false",
                        "16:00 corporate Chrome password read on the same sensitive path")),
                List.of(),
                new ObservedPatternSnapshot(
                        List.of("10.10.0.20"),
                        List.of("8", "9", "10"),
                        List.of("6"),
                        List.of("Chrome/120"),
                        List.of("Windows"),
                        List.of("/admin/api/*"),
                        List.of(),
                        List.of(),
                        List.of()),
                List.of(new CurrentVsObservedDeltaSnapshot(
                        "accessHour",
                        "16",
                        "8, 9, 10",
                        false,
                        "access hour outside observed hours",
                        LearningEvidenceScope.PERSONAL)),
                List.of("CurrentVsObservedDeltaCount"),
                List.of()));

        String section = sections.buildUserProfileNarrative(
                event,
                patterns,
                behaviorAnalysis,
                BaselineStatus.ESTABLISHED);

        assertThat(section).contains("BaselineProfileStatus: ESTABLISHED");
        assertThat(section).contains("WorkProfileEvidenceState: TRUSTED");
        assertThat(section).contains("ObservedPatternEvidenceScope: PERSONAL_BASELINE_PLUS_PERSONAL_RETRIEVED");
        assertThat(section).contains("CurrentAccessHour: 16");
        assertThat(section).contains("CurrentAccessHourPresentInObservedHours: false");
        assertThat(section).contains("CurrentDayPresentInObservedDays: true");
        assertThat(section).contains("CurrentNetworkPresentInObservedNetworks: true");
        assertThat(section).contains("CurrentBrowserPresentInObservedBrowsers: true");
        assertThat(section).contains("CurrentOperatingSystemPresentInObservedOperatingSystems: true");
        assertThat(section).contains("CurrentPathPresentInObservedPaths: true");
        assertThat(section).contains("CurrentVsObservedDeltaCount: 1");
        assertThat(section).contains("StrongestCurrentVsObservedDelta: access hour outside observed hours");
        assertThat(section).contains("CurrentVsObservedDeltaSummary: access hour outside observed hours");
        assertThat(section).contains("CurrentRequestCombinationSeenCount: 0");
        assertThat(section).contains("CurrentRequestCombinationEvidenceScope: PERSONAL_RETRIEVED_SUBSET");
        assertThat(section).contains("CurrentRequestCombinationComparedDimensions: accessHour, authenticationType, browser, actionFamily, resourceFamily, pathFamily");
        assertThat(section).contains("CurrentRequestClosestObservedOverlap: 5/6");
        assertThat(section).contains("StrongestCurrentRequestCombinationDelta: closestOverlap=5/6 | differing=accessHour");
        assertThat(section).contains("CurrentRequestCombinationSummary: hour=16 | auth=PASSWORD | browser=Chrome/120 | action=READ | resource=SENSITIVE | path=/admin/api/*");
        assertThat(section).contains("ObservedComparableCombination1: count=1 | hour=10 | auth=PASSWORD | browser=Chrome/120 | action=READ | resource=SENSITIVE | path=/admin/api/*");
        assertThat(section).contains("BaselineObservations: 20");
    }

    @Test
    @DisplayName("supporting learning context should render supporting baseline and representative comparable evidence")
    void buildSupportingLearningContextSectionShouldRenderSupportingEvidence() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setLearningContextEvidence(new LearningContextEvidence(
                new CurrentLearningContextSnapshot("16", "6", "10.10.0.0/24", "Chrome/120", "Windows", "/admin/api/*", "PASSWORD", "READ", "sensitive"),
                new BaselineEvidenceSnapshot(LearningEvidenceScope.PERSONAL, false, false, 0L, null,
                        List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), ""),
                new BaselineEvidenceSnapshot(LearningEvidenceScope.SUPPORTING, true, true, 20L, 0.82,
                        List.of("10.10.0.0/24"), List.of("9", "10"), List.of("6"), List.of("Chrome/120"), List.of("Windows"),
                        List.of("/admin/api/*"), List.of("PASSWORD"), List.of("READ"), List.of("sensitive"),
                        "Cohort reference baseline matches normal office access."),
                List.of(),
                List.of(new RetrievedBehaviorEvidence(
                        LearningEvidenceScope.SUPPORTING,
                        "finance@tenant-a",
                        "behavior",
                        "artifact-1",
                        0.91,
                        "10.10.0.20",
                        "CORPORATE",
                        "/admin/api/security-test/sensitive/resource-001",
                        "/admin/api/*",
                        "10",
                        "6",
                        "Chrome/120",
                        "Windows",
                        "PASSWORD",
                        "READ",
                        "sensitive",
                        "HIGH",
                        "FINANCE",
                        "12",
                        "false",
                        "10:00 corporate Chrome read on a matching sensitive finance path")),
                new ObservedPatternSnapshot(List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of()),
                List.of(new CurrentVsObservedDeltaSnapshot(
                        "pathFamily",
                        "/admin/api/*",
                        "none",
                        false,
                        "path family unseen in observed paths",
                        LearningEvidenceScope.PERSONAL)),
                List.of("HistoricalComparableCount"),
                List.of()));

        String section = sections.buildSupportingLearningContextSection(behaviorAnalysis);

        assertThat(section).contains("=== SUPPORTING LEARNING CONTEXT ===");
        assertThat(section).contains("SupportingEvidenceMode: REFERENCE_ONLY");
        assertThat(section).contains("SupportingBaselineStatus: AVAILABLE_REFERENCE");
        assertThat(section).contains("SupportingComparableCount: 1");
        assertThat(section).contains("SupportingComparableSummary:");
        assertThat(section).contains("SupportingComparableExample1:");
        assertThat(section).contains("SupportingEvidenceConstraint:");
    }

    @Test
    @DisplayName("buildUserProfileNarrative should mark current-vs-observed comparison as unknown when observed evidence is missing")
    void buildUserProfileNarrativeShouldMarkComparisonUnknownWhenObservedEvidenceMissing() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-baseline-delta-missing-observed")
                .timestamp(LocalDateTime.of(2026, 4, 18, 21, 10))
                .userId("persona_fin_lead")
                .sessionId("session-baseline-delta-missing")
                .sourceIp("10.10.0.20")
                .description("GET /admin/api/security-test/sensitive/self-sensitive-001")
                .build();
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/self-sensitive-001");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineUpdateCount(20L);
        behaviorAnalysis.setLearningContextEvidence(new LearningContextEvidence(
                new CurrentLearningContextSnapshot("21", "6", "CORPORATE", null, "Windows", "/admin/api/*", "PASSWORD", "READ", "SENSITIVE"),
                new BaselineEvidenceSnapshot(LearningEvidenceScope.PERSONAL, true, true, 20L, 0.92,
                        List.of("CORPORATE"), List.of(), List.of(), List.of(), List.of(),
                        List.of(), List.of(), List.of(), List.of(),
                        "Personal office baseline established."),
                new BaselineEvidenceSnapshot(LearningEvidenceScope.SUPPORTING, false, false, 0L, null,
                        List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), ""),
                List.of(),
                List.of(),
                new ObservedPatternSnapshot(
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of()),
                List.of(),
                List.of("CurrentVsObservedDeltaCount", "CurrentAccessHourPresentInObservedHours"),
                List.of("ObservedHours", "ObservedPaths", "ObservedAuthenticationTypes")));

        String section = sections.buildUserProfileNarrative(
                event,
                new SecurityDecisionStandardPromptTemplate.DetectedPatterns(),
                behaviorAnalysis,
                BaselineStatus.ESTABLISHED);

        assertThat(section).contains("CurrentAccessHourPresentInObservedHours: UNKNOWN");
        assertThat(section).contains("CurrentBrowser: UNKNOWN - current value unavailable; do not infer baseline membership");
        assertThat(section).contains("CurrentBrowserPresentInObservedBrowsers: UNKNOWN - current value unavailable; do not infer baseline membership");
        assertThat(section).contains("CurrentVsObservedDeltaCount: UNKNOWN");
        assertThat(section).contains("ObservedPatternEvidenceScope: PERSONAL_BASELINE_ONLY");
        assertThat(section).contains("StrongestCurrentVsObservedDelta: insufficient observed evidence");
        assertThat(section).contains("CurrentVsObservedDeltaSummary: current-vs-observed comparison not reliable");
    }
}
