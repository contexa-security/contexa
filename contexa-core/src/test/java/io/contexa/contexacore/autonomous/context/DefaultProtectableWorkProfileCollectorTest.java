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
package io.contexa.contexacore.autonomous.context;

import java.time.ZoneId;
import io.contexa.contexacore.autonomous.baseline.BaselineView;
import io.contexa.contexacore.autonomous.context.collector.DefaultProtectableWorkProfileCollector;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacore.autonomous.context.collector.ProtectableWorkProfileSnapshot;
import io.contexa.contexacore.autonomous.context.model.ContextFieldTrustRecord;
import io.contexa.contexacore.autonomous.context.model.ContextQualityGrade;

class DefaultProtectableWorkProfileCollectorTest {

    private SecurityContextDataStore dataStore;
    private DefaultProtectableWorkProfileCollector collector;

    @BeforeEach
    void setUp() {
        dataStore = new InMemorySecurityContextDataStore();
        collector = new DefaultProtectableWorkProfileCollector(dataStore);
    }

    @Test
    @DisplayName("collect returns empty when userId is missing")
    void collect_withoutUserId_returnsEmpty() {
        SecurityEvent event = SecurityEvent.builder()
                .timestamp(LocalDateTime.of(2026, 3, 25, 9, 0).atZone(ZoneId.systemDefault()).toInstant())
                .build();

        assertThat(collect(event)).isEmpty();
    }

    @Test
    @DisplayName("collect does not create a personal work profile from the very first allowed request alone")
    void collect_firstAllowedObservationDoesNotCreateSnapshot() {
        SecurityEvent first = event(
                "alice",
                "tenant-acme",
                LocalDateTime.of(2026, 3, 24, 9, 0),
                "/api/customer/list",
                "GET",
                "READ",
                "REPORT",
                "HIGH",
                true,
                true,
                null);

        assertThat(collect(first)).isEmpty();
    }

    @Test
    @DisplayName("collect builds work profile from prior history without contaminating it with the current request")
    void collect_buildsProfileFromPriorHistoryWithoutCurrentRequestContamination() {
        collect(event(
                "alice",
                "tenant-acme",
                LocalDateTime.of(2026, 3, 24, 9, 0),
                "/api/customer/list",
                "GET",
                "READ",
                "REPORT",
                "HIGH",
                true,
                true,
                null));

        ProtectableWorkProfileSnapshot snapshot = collect(event(
                        "alice",
                        "tenant-acme",
                        LocalDateTime.of(2026, 3, 24, 10, 0),
                        "/api/customer/export",
                        "POST",
                        "EXPORT",
                        "REPORT",
                        "HIGH",
                        true,
                        true,
                        null))
                .orElseThrow();

        assertThat(snapshot.getObservationCount()).isEqualTo(1);
        // One observation is below the 7-day minimum sample, so the view reads the 30-day window (W2-3, A-19).
        assertThat(snapshot.getWindowDays()).isEqualTo(30);
        assertThat(snapshot.getFrequentProtectableResources()).containsExactly("/api/customer/list");
        assertThat(snapshot.getFrequentActionFamilies()).containsExactly("READ");
        assertThat(snapshot.getNormalAccessHours()).containsExactly(9);
        assertThat(snapshot.getNormalAccessDays())
                .containsExactly(LocalDate.of(2026, 3, 24).getDayOfWeek().getValue());
        assertThat(snapshot.getNormalRequestRate()).isEqualTo(1.0d);
        assertThat(snapshot.getProtectableInvocationDensity()).isEqualTo(1.0d);
        assertThat(snapshot.getProtectableResourceHeatmap()).containsExactly("/api/customer/list=1");
        assertThat(snapshot.getFrequentSensitiveResourceCategories()).containsExactly("HIGH");
        assertThat(snapshot.getNormalReadWriteExportRatio()).isEqualTo("100:0:0");
        assertThat(snapshot.getSummary()).contains("Observed protectable resources /api/customer/list");
        assertThat(snapshot.getSummary()).contains("Evidence state PROVISIONAL");
        assertThat(snapshot.getTrustProfile()).isNotNull();
        assertThat(snapshot.getTrustProfile().getOverallQualityGrade()).isEqualTo(ContextQualityGrade.WEAK);
        assertThat(snapshot.getTrustProfile().getFieldRecords())
                .extracting(ContextFieldTrustRecord::getFieldPath)
                .contains("workProfile.frequentProtectableResources", "workProfile.frequentActionFamilies");
    }

    @Test
    @DisplayName("collect does not promote resource family fallback into frequent protectable resources")
    void collect_doesNotTreatResourceFamilyAsProtectableResource() {
        SecurityEvent first = SecurityEvent.builder()
                .userId("alice")
                .timestamp(LocalDateTime.of(2026, 3, 24, 9, 0).atZone(ZoneId.systemDefault()).toInstant())
                .description("GET missing-path")
                .build();
        first.addMetadata("tenantId", "tenant-acme");
        first.addMetadata("httpMethod", "GET");
        first.addMetadata("actionFamily", "READ");
        first.addMetadata("currentResourceFamily", "REPORT");
        first.addMetadata("resourceSensitivity", "HIGH");
        first.addMetadata("isProtectable", true);
        first.addMetadata("granted", true);

        assertThat(collect(first)).isEmpty();

        SecurityEvent second = SecurityEvent.builder()
                .userId("alice")
                .timestamp(LocalDateTime.of(2026, 3, 24, 10, 0).atZone(ZoneId.systemDefault()).toInstant())
                .description("GET missing-path-2")
                .build();
        second.addMetadata("tenantId", "tenant-acme");
        second.addMetadata("httpMethod", "GET");
        second.addMetadata("actionFamily", "READ");
        second.addMetadata("currentResourceFamily", "REPORT");
        second.addMetadata("resourceSensitivity", "HIGH");
        second.addMetadata("isProtectable", true);
        second.addMetadata("granted", true);

        ProtectableWorkProfileSnapshot snapshot = collect(second).orElseThrow();

        assertThat(snapshot.getFrequentProtectableResources()).isEmpty();
        assertThat(snapshot.getTrustProfile()).isNotNull();
        assertThat(snapshot.getTrustProfile().getFieldRecords())
                .filteredOn(record -> "workProfile.frequentProtectableResources".equals(record.getFieldPath()))
                .singleElement()
                .satisfies(record -> {
                    assertThat(record.getQualityGrade()).isEqualTo(ContextQualityGrade.REJECTED);
                    assertThat(record.getUnknownRate()).isEqualTo(1.0d);
                });
    }

    @Test
    @DisplayName("collect excludes denied requests from future baseline and keeps protectable density relative to total requests")
    void collect_excludesDeniedRequestsAndKeepsDensityRelativeToTotalRequests() {
        collect(event(
                "alice",
                "tenant-acme",
                LocalDateTime.of(2026, 3, 23, 9, 0),
                "/dashboard",
                "GET",
                "READ",
                "DASHBOARD",
                "LOW",
                false,
                true,
                null));
        collect(event(
                "alice",
                "tenant-acme",
                LocalDateTime.of(2026, 3, 23, 10, 0),
                "/api/customer/list",
                "GET",
                "READ",
                "REPORT",
                "HIGH",
                true,
                true,
                null));
        collect(event(
                "alice",
                "tenant-acme",
                LocalDateTime.of(2026, 3, 23, 11, 0),
                "/api/customer/export",
                "POST",
                "EXPORT",
                "REPORT",
                "HIGH",
                true,
                false,
                "BLOCK"));

        ProtectableWorkProfileSnapshot snapshot = collect(event(
                        "alice",
                        "tenant-acme",
                        LocalDateTime.of(2026, 3, 23, 12, 0),
                        "/api/customer/update",
                        "PATCH",
                        "UPDATE",
                        "REPORT",
                        "HIGH",
                        true,
                        true,
                        null))
                .orElseThrow();

        assertThat(snapshot.getObservationCount()).isEqualTo(2);
        assertThat(snapshot.getFrequentProtectableResources()).containsExactly("/api/customer/list");
        assertThat(snapshot.getFrequentActionFamilies()).containsExactly("READ");
        assertThat(snapshot.getProtectableInvocationDensity()).isEqualTo(0.5d);
        assertThat(snapshot.getNormalReadWriteExportRatio()).isEqualTo("100:0:0");
        assertThat(snapshot.getSummary()).contains("Protectable density 0.50");
    }

    @Test
    @DisplayName("an export counts as an export and a download as a read, in one vocabulary with stored families (W2-1)")
    void collect_countsActionsInOneVocabulary() {
        SecurityEvent download = event("alice", "tenant-acme", LocalDateTime.of(2026, 3, 24, 9, 0),
                "/api/documents/D-1/download", "GET", null, "REPORT", "HIGH", true, true, null);
        download.addMetadata("protectableMethod", "io.contexa.example.BusinessOperations.downloadDocument");
        collect(download);
        collect(event("alice", "tenant-acme", LocalDateTime.of(2026, 3, 24, 9, 10),
                "/api/documents/D-2", "GET", "READ", "REPORT", "HIGH", true, true, null));
        collect(event("alice", "tenant-acme", LocalDateTime.of(2026, 3, 24, 9, 20),
                "/api/notes", "POST", "CREATE", "REPORT", "HIGH", true, true, null));
        SecurityEvent export = event("alice", "tenant-acme", LocalDateTime.of(2026, 3, 24, 9, 30),
                "/api/projects/P-1/exports", "POST", null, "REPORT", "HIGH", true, true, null);
        export.addMetadata("protectableMethod", "io.contexa.example.BusinessOperations.exportDocuments");
        collect(export);

        ProtectableWorkProfileSnapshot snapshot = collect(event("alice", "tenant-acme",
                        LocalDateTime.of(2026, 3, 24, 10, 0), "/api/documents/D-3", "GET", "READ", "REPORT", "HIGH",
                        true, true, null))
                .orElseThrow();

        // A-5: the usual ratio counted a bulk export as a write (50:50:0).
        assertThat(snapshot.getNormalReadWriteExportRatio()).isEqualTo("50:25:25");
        assertThat(snapshot.getFrequentActionFamilies()).containsExactlyInAnyOrder("READ", "WRITE", "EXPORT");
    }

    @Test
    void collect_takesTheUsualHoursFromTheBaselineView() {
        for (int index = 0; index < 12; index++) {
            collect(event("alice", "tenant-acme", LocalDateTime.of(2026, 3, 24, index < 10 ? 9 : 15, index),
                    "/api/documents/D-" + index, "GET", "READ", "REPORT", "HIGH", true, true, null));
        }

        ProtectableWorkProfileSnapshot snapshot = collect(event("alice", "tenant-acme",
                        LocalDateTime.of(2026, 3, 24, 16, 0), "/api/documents/D-12", "GET", "READ", "REPORT", "HIGH",
                        true, true, null))
                .orElseThrow();

        // B-9: the work profile's usual hours are the view's (the top six by count used to make 15:00 usual too).
        BaselineView view = snapshot.getBaselineView();
        assertThat(view.observations()).isEqualTo(12);
        assertThat(snapshot.getNormalAccessHours()).isEqualTo(view.usualHours()).containsExactly(9);
        assertThat(view.seenHours()).containsExactly(9, 15);
        assertThat(snapshot.getNormalRequestRate()).isEqualTo(view.requestsPerActiveHour());
        // The days of the week read several weeks, so the summary says which observations they count (W2-3 correction).
        assertThat(snapshot.getSummary()).startsWith("Window 7d | Observations 12 | Days of week from 30d, 12 observations");
    }

    @Test
    void collect_givesTheViewTheTrustProfileCautionsAsCauses() {
        for (int index = 0; index < 12; index++) {
            SecurityEvent read = event("alice", "tenant-acme", LocalDateTime.of(2026, 3, 24, 9, index),
                    "/api/documents/D-" + index, "GET", "READ", "REPORT", "HIGH", true, true, null);
            read.getMetadata().remove("isProtectable");
            collect(read);
        }

        ProtectableWorkProfileSnapshot snapshot = collect(event("alice", "tenant-acme",
                        LocalDateTime.of(2026, 3, 24, 10, 0), "/api/documents/D-12", "GET", "READ", "REPORT", "HIGH",
                        true, true, null))
                .orElseThrow();

        // Declared actions, but the protectable flag was read from the class and method names: the trust profile
        // needs caution there, so the view cannot say TRUSTED beside it (B-2).
        assertThat(snapshot.getBaselineView().evidenceGrade()).isEqualTo(BaselineView.EvidenceGrade.LIMITED);
        assertThat(snapshot.getBaselineView().evidenceCauses())
                .anyMatch(cause -> cause.startsWith("workProfile.protectableInvocationDensity needs caution: observations=12")
                        && cause.endsWith("fallbackSources=className+methodName"));
        assertThat(snapshot.getBaselineView().workProfileEvidenceState()).isEqualTo("PROVISIONAL");
    }

    @Test
    void collect_widensTheWindowWhenTheLastWeekIsTooThin() {
        for (int day = 0; day < 10; day++) {
            collect(event("alice", "tenant-acme", LocalDateTime.of(2026, 3, 1 + day, 10, 0),
                    "/api/documents/D-" + day, "GET", "READ", "REPORT", "HIGH", true, true, null));
        }
        for (int day = 0; day < 3; day++) {
            collect(event("alice", "tenant-acme", LocalDateTime.of(2026, 3, 21 + day, 10, 0),
                    "/api/documents/E-" + day, "GET", "READ", "REPORT", "HIGH", true, true, null));
        }

        ProtectableWorkProfileSnapshot snapshot = collect(event("alice", "tenant-acme",
                        LocalDateTime.of(2026, 3, 24, 10, 30), "/api/documents/E-9", "GET", "READ", "REPORT", "HIGH",
                        true, true, null))
                .orElseThrow();

        // A-19: three requests in the last week used to stand for the subject; the month does.
        assertThat(snapshot.getObservationCount()).isEqualTo(13);
        assertThat(snapshot.getWindowDays()).isEqualTo(30);
        assertThat(snapshot.getBaselineView().evidenceCauses())
                .contains("the last 7 days hold 3 observations, below the minimum 10; the view uses the last 30 days");
        assertThat(snapshot.getSummary()).startsWith("Window 30d | Observations 13 |")
                .doesNotContain("Days of week from");
    }

    @Test
    void collect_keepsTheTemplateAndTheSessionToBindTargetsAndSessionLength() {
        LocalDateTime start = LocalDateTime.of(2026, 3, 24, 9, 0);
        String[] sessions = {"session-a", "session-b", "session-c"};
        long[] spans = {30L, 10L, 20L};
        for (int index = 0; index < sessions.length; index++) {
            for (long minute : new long[]{0L, spans[index]}) {
                SecurityEvent export = event("alice", "tenant-acme", start.plusDays(index).plusMinutes(minute),
                        "/api/projects/PLM-OPS/exports", "POST", "EXPORT", "REPORT", "HIGH", true, true, null);
                export.addMetadata("protectableResourceUrl", "/api/projects/{projectKey}/exports");
                export.setSessionId(sessions[index]);
                collect(export);
            }
        }

        ProtectableWorkProfileSnapshot snapshot = collect(event("alice", "tenant-acme",
                        start.plusDays(3), "/api/documents/D-1", "GET", "READ", "REPORT", "HIGH", true, true, null))
                .orElseThrow();

        // The stored observations keep the URL template and a session key (v3), so the view binds the target and the
        // sessions' spans; the raw session id is not stored.
        assertThat(snapshot.getBaselineView().usualTargets()).containsExactly("projectKey=PLM-OPS");
        assertThat(snapshot.getBaselineView().usualSessionMinutes()).isEqualTo(20);
        assertThat(String.join("\n", dataStore.getRecentWorkProfileObservations("tenant-acme", "alice", 10)))
                .startsWith("v4|")
                .doesNotContain("session-a");
    }

    @Test
    void collect_keepsTheItemCountOfAnExportAndStillReadsAV3Observation() {
        LocalDateTime start = LocalDateTime.of(2026, 3, 24, 9, 0);
        SecurityEvent export = event("alice", "tenant-acme", start, "/api/projects/PLM-OPS/exports", "POST", "EXPORT",
                "REPORT", "HIGH", true, true, null);
        export.addMetadata("requestItems", 40);
        collect(export);
        String stored = dataStore.getRecentWorkProfileObservations("tenant-acme", "alice", 10).get(0);

        ProtectableWorkProfileSnapshot snapshot = collect(event("alice", "tenant-acme", start.plusHours(1),
                "/api/documents/D-1", "GET", "READ", "REPORT", "HIGH", true, true, null)).orElseThrow();

        // W2-6 (P2-CHANGE-4): the observation keeps the export's item count, and the view states the usual export size.
        assertThat(stored).startsWith("v4|");
        assertThat(snapshot.getBaselineView().exportSize()).isEqualTo(new BaselineView.ExportSize(1, 40, 40));

        // An observation stored before (v3) reads without an item count.
        InMemorySecurityContextDataStore older = new InMemorySecurityContextDataStore();
        older.addWorkProfileObservation("tenant-acme", "alice", "v3" + stored.substring(2, stored.lastIndexOf('|')));
        ProtectableWorkProfileSnapshot fromV3 = new DefaultProtectableWorkProfileCollector(older).collect(event("alice",
                "tenant-acme", start.plusHours(1), "/api/documents/D-1", "GET", "READ", "REPORT", "HIGH", true, true,
                null)).orElseThrow();
        assertThat(fromV3.getBaselineView().observations()).isEqualTo(1);
        assertThat(fromV3.getBaselineView().exportSize()).isNull();
    }

    @Test
    void collect_leavesTheActivityPeriodOfTheRequestOutOfTheUsualBehaviour() {
        LocalDateTime start = LocalDateTime.of(2026, 3, 24, 9, 0);
        SecurityEvent earlier = event("alice", "tenant-acme", start, "/api/documents/D-0", "GET", "READ", "REPORT",
                "HIGH", true, true, null);
        earlier.setSessionId("session-a");
        collect(earlier);
        for (int index = 0; index < 3; index++) {
            SecurityEvent read = event("alice", "tenant-acme", start.plusDays(1).plusMinutes(index),
                    "/api/customers/CUS-" + index, "GET", "READ", "REPORT", "HIGH", true, true, null);
            read.setSessionId("session-a");
            collect(read);
        }

        SecurityEvent current = event("alice", "tenant-acme", start.plusDays(1).plusMinutes(3),
                "/api/customers/CUS-3", "GET", "READ", "REPORT", "HIGH", true, true, null);
        current.setSessionId("session-a");
        ProtectableWorkProfileSnapshot snapshot = collect(current).orElseThrow();

        // The three reads a minute apart are the period being judged; only the earlier day of the same session key is
        // usual behaviour.
        assertThat(snapshot.getBaselineView().observations()).isEqualTo(1);
    }

    @Test
    void collect_leavesOutThePeriodBeingJudgedUnderTheSessionsEarlierId() {
        LocalDateTime start = LocalDateTime.of(2026, 3, 24, 9, 0);
        SecurityEvent earlier = event("alice", "tenant-acme", start, "/api/documents/D-0", "GET", "READ", "REPORT",
                "HIGH", true, true, null);
        earlier.setSessionId("session-a");
        collect(earlier);
        for (int index = 0; index < 3; index++) {
            SecurityEvent read = event("alice", "tenant-acme", start.plusDays(1).plusMinutes(index),
                    "/api/customers/CUS-" + index, "GET", "READ", "REPORT", "HIGH", true, true, null);
            read.setSessionId("session-a");
            collect(read);
        }
        // A step-up check gives the session a new id (session fixation protection).
        dataStore.moveSessionRecords("session-a", "session-b");

        SecurityEvent current = event("alice", "tenant-acme", start.plusDays(1).plusMinutes(3),
                "/api/customers/CUS-3", "GET", "READ", "REPORT", "HIGH", true, true, null);
        current.setSessionId("session-b");
        ProtectableWorkProfileSnapshot snapshot = collect(current).orElseThrow();

        // The three reads under the old id are still the period being judged (P2 correction 5).
        assertThat(snapshot.getBaselineView().observations()).isEqualTo(1);
    }

    @Test
    void collect_neverCountsAFamilyHintAsTheUsualClass() {
        for (int index = 0; index < 4; index++) {
            collect(event("alice", "tenant-acme", LocalDateTime.of(2026, 3, 24, 9, index),
                    "/api/releases/R-" + index, "GET", "READ", "PUBLIC_RELEASES", null, true, true, null));
        }
        SecurityEvent typed = event("alice", "tenant-acme", LocalDateTime.of(2026, 3, 24, 9, 10),
                "/api/releases/R-4", "GET", "READ", null, null, true, true, null);
        typed.addMetadata("resourceType", "CONFIDENTIAL");
        collect(typed);

        ProtectableWorkProfileSnapshot snapshot = collect(event("alice", "tenant-acme",
                        LocalDateTime.of(2026, 3, 24, 9, 20), "/api/releases/R-5", "GET", "READ", "PUBLIC_RELEASES",
                        null, true, true, null))
                .orElseThrow();

        // W2-10: the category's word PUBLIC is no class; a classification value in the type still is one.
        assertThat(snapshot.getBaselineView().observations()).isEqualTo(5);
        assertThat(snapshot.getBaselineView().resourceClasses()).containsExactly("SENSITIVE=1");
    }

    @Test
    void collect_countsAClassifyingTypeEvenWhenACategoryIsDeclared() {
        for (int index = 0; index < 3; index++) {
            SecurityEvent declared = event("alice", "tenant-acme", LocalDateTime.of(2026, 3, 24, 9, index),
                    "/api/releases/R-" + index, "GET", "READ", null, null, true, true, null);
            declared.addMetadata("resourceCategory", "RELEASE_NOTES");
            declared.addMetadata("resourceType", "CONFIDENTIAL");
            collect(declared);
        }

        ProtectableWorkProfileSnapshot snapshot = collect(event("alice", "tenant-acme",
                        LocalDateTime.of(2026, 3, 24, 9, 20), "/api/releases/R-5", "GET", "READ", null, "HIGH",
                        true, true, null))
                .orElseThrow();

        // W2-11: the category is the family; the type's classification still counts as the class, as in the context.
        assertThat(snapshot.getBaselineView().resourceClasses()).containsExactly("SENSITIVE=3");
    }

    @Test
    @DisplayName("a request learned after its verification is an observation at its weight and its own time (W5-2)")
    void recordVerified_keepsTheRequestAtItsWeightAndItsOwnTime() {
        LocalDateTime night = LocalDateTime.of(2026, 3, 24, 3, 17);
        SecurityEvent export = event("alice", "tenant-acme", night, "/api/projects/PLM-OPS/exports", "POST", "EXPORT",
                "REPORT", "HIGH", true, true, null);
        export.addMetadata("requestItems", 4831);

        collector.recordVerified(export, 0.5);

        List<String> stored = dataStore.getRecentWorkProfileObservations("tenant-acme", "alice", 10);
        assertThat(stored).singleElement().satisfies(line -> {
            assertThat(line).startsWith("v5|").endsWith("|0.5");
            assertThat(line.split("\\|", -1)[2])
                    .isEqualTo(String.valueOf(night.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli()));
        });
        ProtectableWorkProfileSnapshot snapshot = collect(event("alice", "tenant-acme", night.plusHours(6),
                "/api/documents/D-1", "GET", "READ", "REPORT", "HIGH", true, true, null)).orElseThrow();
        assertThat(snapshot.getBaselineView().observations()).isEqualTo(1);
        assertThat(snapshot.getBaselineView().exportSize()).isEqualTo(new BaselineView.ExportSize(1, 4831, 4831));
        // A whole weight keeps the ordinary form.
        collector.recordVerified(event("bob", "tenant-acme", night, "/api/documents/D-2", "GET", "READ", "REPORT",
                "HIGH", true, true, null), 1.0);
        assertThat(dataStore.getRecentWorkProfileObservations("tenant-acme", "bob", 10)).singleElement()
                .satisfies(line -> assertThat(line).startsWith("v4|"));
    }

    private SecurityEvent event(
            String userId,
            String tenantId,
            LocalDateTime timestamp,
            String requestPath,
            String httpMethod,
            String actionFamily,
            String resourceFamily,
            String sensitivity,
            boolean protectable,
            boolean granted,
            String decisionResult) {
        SecurityEvent event = SecurityEvent.builder()
                .userId(userId)
                .timestamp(timestamp.atZone(ZoneId.systemDefault()).toInstant())
                .description(httpMethod + " " + requestPath)
                .build();
        event.addMetadata("tenantId", tenantId);
        event.addMetadata("requestPath", requestPath);
        event.addMetadata("httpMethod", httpMethod);
        event.addMetadata("actionFamily", actionFamily);
        event.addMetadata("currentResourceFamily", resourceFamily);
        event.addMetadata("resourceSensitivity", sensitivity);
        event.addMetadata("isProtectable", protectable);
        event.addMetadata("granted", granted);
        if (decisionResult != null) {
            event.addMetadata("decisionResult", decisionResult);
        }
        if (protectable) {
            event.addMetadata("className", "io.contexa.CustomerController");
            event.addMetadata("methodName", "handle");
        }
        return event;
    }

    /** One request seen through to an enforced ALLOW, the way the pipeline records it (W2-7). */
    private Optional<ProtectableWorkProfileSnapshot> collect(SecurityEvent event) {
        Optional<ProtectableWorkProfileSnapshot> snapshot = collector.collect(event);
        collector.recorder().commit(event, "ALLOW", true);
        return snapshot;
    }
}
