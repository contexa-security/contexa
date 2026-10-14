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

import java.time.ZoneId;
import java.time.ZoneOffset;
import io.contexa.contexacore.autonomous.baseline.BaselineView;
import io.contexa.contexacore.autonomous.baseline.BaselineViewCalculator;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidenceAssembler;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
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
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionPromptSectionsBaselineDeltaTest {

    @Test
    @DisplayName("buildUserProfileNarrative should expose current-vs-observed baseline deltas")
    void buildUserProfileNarrativeShouldExposeCurrentVsObservedDeltas() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-baseline-delta-001")
                .timestamp(LocalDateTime.of(2026, 4, 18, 16, 4).atZone(ZoneId.systemDefault()).toInstant())
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
        // W2-4: one device line; a baseline without device pairs compares the browser and the system one by one.
        assertThat(section).contains("CurrentDevice: Chrome/120 on WINDOWS");
        assertThat(section).contains("CurrentDevicePresentInObservedDevices: true");
        assertThat(section).doesNotContain("\nObservedDevices:");
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

        String withoutRepeatedState = sections.buildUserProfileNarrative(
                event,
                patterns,
                behaviorAnalysis,
                BaselineStatus.ESTABLISHED,
                false);

        assertThat(withoutRepeatedState).contains("BaselineProfileStatus: ESTABLISHED")
                .contains("CurrentAccessHourPresentInObservedHours: false")
                .doesNotContain("WorkProfileEvidenceState:");
    }

    @Test
    void theDeviceIsOneLineComparedByTheLearnedPairs() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-device-001")
                .timestamp(LocalDateTime.of(2026, 4, 17, 10, 4).atZone(ZoneId.systemDefault()).toInstant())
                .userId("alice")
                .sessionId("session-device")
                .sourceIp("10.10.0.20")
                .build();
        event.addMetadata("requestPath", "/api/reports/r-1");
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(new BaselineEvidenceSnapshot(LearningEvidenceScope.PERSONAL, true,
                true, 20L, 0.9, List.of("10.10.0"), List.of("10"), List.of("5"), List.of("Chrome/120", "Safari/18"),
                List.of("Mac", "Windows"), List.of("/api/reports/{id}"), List.of("PASSWORD"), List.of("READ"),
                List.of("NORMAL"), "personal baseline established", BaselineEvidenceStatus.AVAILABLE, "",
                List.of("Chrome/120 on WINDOWS", "Safari/18 on MAC")));
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .device(CanonicalSecurityContext.Device.builder().browser("Safari").browserVersion("18").os("WINDOWS").build())
                .location(CanonicalSecurityContext.Location.builder().ipBand("10.10.0.0/24").build())
                .build();
        behaviorAnalysis.setLearningContextEvidence(
                new LearningContextEvidenceAssembler().assemble("alice", event, context, behaviorAnalysis, List.of()));

        String section = sections.buildUserProfileNarrative(event,
                new SecurityDecisionStandardPromptTemplate.DetectedPatterns(), behaviorAnalysis, BaselineStatus.ESTABLISHED);

        // A learned prefix is the same band; the browser and the system were each seen, never together: one delta.
        assertThat(section)
                .contains("CurrentNetworkPresentInObservedNetworks: true")
                .contains("ObservedNetworks: 10.10.0.0/24")
                .contains("ObservedOperatingSystems: MAC, WINDOWS")
                .contains("CurrentBrowserPresentInObservedBrowsers: true")
                .contains("CurrentOperatingSystemPresentInObservedOperatingSystems: true")
                .contains("CurrentDevice: Safari/18 on WINDOWS")
                .contains("CurrentDevicePresentInObservedDevices: false")
                .contains("ObservedDevices: Chrome/120 on WINDOWS, Safari/18 on MAC")
                .contains("CurrentVsObservedDeltaCount: 1")
                .contains("CurrentVsObservedDeltaSummary: device outside observed devices");
    }

    @Test
    @DisplayName("supporting learning context should render supporting baseline and representative comparable evidence")
    void buildSupportingLearningContextSectionShouldRenderSupportingEvidence() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

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
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-baseline-delta-missing-observed")
                .timestamp(LocalDateTime.of(2026, 4, 18, 21, 10).atZone(ZoneId.systemDefault()).toInstant())
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

    @Test
    @DisplayName("buildUserProfileNarrative should name the request's action as the context gives it without learning evidence")
    void buildUserProfileNarrativeShouldNameTheActionTheContextGivesTheRequestWithoutLearningEvidence() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-export-without-learning-evidence")
                .timestamp(LocalDateTime.of(2026, 4, 18, 3, 17).atZone(ZoneId.systemDefault()).toInstant())
                .userId("persona_fin_lead")
                .sessionId("session-export")
                .sourceIp("10.10.0.20")
                .build();
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("protectableMethod", "io.contexa.example.BusinessOperations.exportDocuments");

        String section = sections.buildUserProfileNarrative(
                event,
                new SecurityDecisionStandardPromptTemplate.DetectedPatterns(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                BaselineStatus.ESTABLISHED);

        // A bulk export sent as a POST is an export here as in the context, not a write read from the HTTP method.
        assertThat(section).contains("CurrentActionFamily: EXPORT").doesNotContain("CurrentActionFamily: WRITE");
    }

    @Test
    @DisplayName("the user profile states the work profile evidence of the one baseline view and the session rate in its unit")
    void theUserProfileAndTheSessionTimelineReadTheBaselineView() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());
        List<BaselineViewCalculator.Observation> observations = new ArrayList<>();
        long now = LocalDateTime.of(2026, 10, 7, 14, 0).toInstant(ZoneOffset.UTC).toEpochMilli();
        for (int index = 0; index < 20; index++) {
            observations.add(new BaselineViewCalculator.Observation(
                    LocalDateTime.of(2026, 10, 6, 10 + index % 4, index).toInstant(ZoneOffset.UTC).toEpochMilli(),
                    "READ", "protectableMethod", true, "INTERNAL", null, "/api/documents/D-" + index, null, true));
        }
        BaselineView view = BaselineViewCalculator.calculate(observations, now, ZoneOffset.UTC);
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setLearningContextEvidence(new LearningContextEvidence(
                new CurrentLearningContextSnapshot("10", "2", "CORPORATE", null, "Windows", "/api/documents/*", "PASSWORD", "READ", "NORMAL"),
                null, null, List.of(), List.of(),
                new ObservedPatternSnapshot(List.of(), List.of("10", "11", "12", "13"), List.of(), List.of(), List.of(),
                        List.of(), List.of(), List.of(), List.of()),
                List.of(), List.of(), List.of(), view));
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-baseline-view")
                .timestamp(LocalDateTime.of(2026, 10, 7, 10, 0).atZone(ZoneId.systemDefault()).toInstant())
                .userId("persona_fin_lead")
                .build();

        String profile = sections.buildUserProfileNarrative(event, new SecurityDecisionStandardPromptTemplate.DetectedPatterns(),
                behaviorAnalysis, BaselineStatus.ESTABLISHED);
        SecurityDecisionStandardPromptTemplate.SessionContext session = new SecurityDecisionStandardPromptTemplate.SessionContext();
        session.setSessionAgeMinutes(90);
        session.setRequestCount(10);
        String timeline = sections.buildSessionTimelineSection(session, behaviorAnalysis);

        // B-2: an established baseline whose actions are inferred is still provisional evidence, as the work profile says.
        assertThat(profile).contains("WorkProfileEvidenceState: PROVISIONAL").doesNotContain("WorkProfileEvidenceState: TRUSTED");
        // S-29: 10 requests over the 2 hours the session spans against the usual 5 per active hour.
        assertThat(view.requestsPerActiveHour()).isEqualTo(5.0);
        assertThat(timeline)
                .contains("SessionRequestsPerMinute: 0.1")
                .contains("SessionRequestsPerActiveHour: 5.00")
                .contains("BaselineRequestsPerActiveHour: 5.00")
                .contains("SessionRateVsBaseline: 1.0x")
                .doesNotContain("BaselineRequestsPerMinute");
    }

    @Test
    @DisplayName("buildUserProfileNarrative should name the request's path family as the host's URL template without learning evidence")
    void buildUserProfileNarrativeShouldNameThePathFamilyAsTheHostsUrlTemplateWithoutLearningEvidence() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-read-without-learning-evidence")
                .timestamp(LocalDateTime.of(2026, 4, 18, 10, 5).atZone(ZoneId.systemDefault()).toInstant())
                .userId("persona_fin_lead")
                .sessionId("session-read")
                .sourceIp("10.10.0.20")
                .build();
        event.addMetadata("requestPath", "/api/documents/HX-310-DWG-00001");
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("protectableResourceUrl", "/api/documents/{documentKey}");

        String section = sections.buildUserProfileNarrative(
                event,
                new SecurityDecisionStandardPromptTemplate.DetectedPatterns(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                BaselineStatus.ESTABLISHED);

        // Reading another document is the same kind of request here as in the context (W2-2).
        assertThat(section).contains("CurrentPathFamily: /api/documents/{documentKey}")
                .doesNotContain("CurrentPathFamily: /api/documents/HX-310-DWG-00001");
    }

    @Test
    @DisplayName("buildUserProfileNarrative should never take the request's class from a family hint without learning evidence (W2-10)")
    void buildUserProfileNarrativeShouldNeverTakeTheClassFromAFamilyHintWithoutLearningEvidence() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent hinted = SecurityEvent.builder()
                .eventId("event-release-hint-without-learning-evidence")
                .timestamp(LocalDateTime.of(2026, 4, 18, 10, 5).atZone(ZoneId.systemDefault()).toInstant())
                .userId("persona_fin_lead")
                .sessionId("session-read")
                .sourceIp("10.10.0.20")
                .build();
        hinted.addMetadata("requestPath", "/api/releases/R-1");
        hinted.addMetadata("httpMethod", "GET");
        hinted.addMetadata("resourceFamily", "PUBLIC_RELEASES");
        SecurityEvent classified = SecurityEvent.builder()
                .eventId("event-release-class-without-learning-evidence")
                .timestamp(LocalDateTime.of(2026, 4, 18, 10, 6).atZone(ZoneId.systemDefault()).toInstant())
                .userId("persona_fin_lead")
                .sessionId("session-read")
                .sourceIp("10.10.0.20")
                .build();
        classified.addMetadata("requestPath", "/api/releases/R-1");
        classified.addMetadata("httpMethod", "GET");
        classified.addMetadata("resourceFamily", "PUBLIC_RELEASES");
        classified.addMetadata("resourceSensitivity", "CONFIDENTIAL");

        String hintedSection = sections.buildUserProfileNarrative(hinted,
                new SecurityDecisionStandardPromptTemplate.DetectedPatterns(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(), BaselineStatus.ESTABLISHED);
        String classifiedSection = sections.buildUserProfileNarrative(classified,
                new SecurityDecisionStandardPromptTemplate.DetectedPatterns(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(), BaselineStatus.ESTABLISHED);

        // The word PUBLIC in the category's name is no class; the sensitivity is one.
        assertThat(hintedSection).doesNotContain("CurrentResourceFamily: PUBLIC");
        assertThat(classifiedSection).contains("CurrentResourceFamily: SENSITIVE");
    }
}
