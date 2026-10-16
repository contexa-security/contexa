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
import io.contexa.contexacore.autonomous.context.collector.DefaultRoleScopeCollector;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.contexa.contexacore.autonomous.context.support.VocabularyVersion;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacore.autonomous.context.collector.RoleScopeSnapshot;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;

class DefaultRoleScopeCollectorTest {

    private SecurityContextDataStore dataStore;
    private DefaultRoleScopeCollector collector;

    @BeforeEach
    void setUp() {
        dataStore = new InMemorySecurityContextDataStore();
        collector = new DefaultRoleScopeCollector(dataStore);
    }

    @Test
    @DisplayName("collect builds role scope from prior authorized history without contaminating it with the current request")
    void collect_buildsRoleScopeFromPriorAuthorizedHistory() {
        collect(peerEvent(
                LocalDateTime.of(2026, 3, 26, 9, 0),
                List.of("ROLE_ANALYST"),
                List.of("customer_data"),
                List.of("report.read"),
                "READ",
                "REPORT",
                true));
        // The permission state is the user's own (W5-10 D8: the group's usual scope is the other members').
        collect(event(
                LocalDateTime.of(2026, 3, 26, 9, 5),
                List.of("ROLE_ANALYST"),
                List.of("customer_data"),
                List.of("report.read"),
                "READ",
                "REPORT",
                true));

        RoleScopeSnapshot snapshot = collect(event(
                        LocalDateTime.of(2026, 3, 26, 10, 0),
                        List.of("ROLE_ANALYST"),
                        List.of("customer_data"),
                        List.of("report.read", "report.export"),
                        "EXPORT",
                        "REPORT",
                        true))
                .orElseThrow();

        assertThat(snapshot.getExpectedResourceFamilies()).containsExactly("REPORT");
        assertThat(snapshot.getExpectedActionFamilies()).containsExactly("READ");
        assertThat(snapshot.getResourceFamilyDrift()).isFalse();
        assertThat(snapshot.getActionFamilyDrift()).isTrue();
        assertThat(snapshot.getRecentPermissionChanges()).containsExactly("Authorization scope changed: permissions changed");
        assertThat(snapshot.getSummary()).contains("Effective roles ROLE_ANALYST");
        assertThat(snapshot.getTrustProfile()).isNotNull();
        assertThat(snapshot.getTrustProfile().getProfileKey()).isEqualTo("ROLE_SCOPE_PROFILE");
    }

    @Test
    @DisplayName("a request the decision challenged joins no scope, while its permission state is kept (W2-7, S-10)")
    void aChallengedRequestJoinsNoScopeButItsPermissionStateIsKept() {
        SecurityEvent challenged = event(LocalDateTime.of(2026, 3, 26, 9, 0), List.of("ROLE_ANALYST"),
                List.of("customer_data"), List.of("report.read"), "EXPORT", "CUSTOMER", true);
        collector.collect(challenged);
        collector.recorder().commit(challenged, "CHALLENGE", true);

        RoleScopeSnapshot snapshot = collect(event(LocalDateTime.of(2026, 3, 26, 10, 0), List.of("ROLE_ANALYST"),
                List.of("customer_data"), List.of("report.read", "report.export"), "READ", "REPORT", true))
                .orElseThrow();

        // The authorization allowed the export, but the decision did not: the scope group learns nothing from it.
        assertThat(snapshot.getExpectedActionFamilies()).doesNotContain("EXPORT");
        assertThat(snapshot.getExpectedResourceFamilies()).doesNotContain("CUSTOMER");
        // The authorization state of the challenged request is the one the next request is compared with.
        assertThat(snapshot.getRecentPermissionChanges()).containsExactly("Authorization scope changed: permissions changed");
    }

    @Test
    @DisplayName("a refused authorization is recorded as denied scope under its own outcome (W2-7)")
    void aRefusedAuthorizationIsRecordedAsDeniedScope() {
        SecurityEvent refused = event(LocalDateTime.of(2026, 3, 26, 9, 30), List.of("ROLE_ANALYST"),
                List.of("customer_data"), List.of("report.read"), "DELETE", "ACCOUNT", false);
        collector.collect(refused);
        // The authorization denial recorder commits the refusal; no Zero Trust decision ever allows it.
        collector.recorder().commit(refused, SessionDecisionRecord.AUTHORIZATION_DENIED, true);

        RoleScopeSnapshot snapshot = collect(event(LocalDateTime.of(2026, 3, 26, 10, 0), List.of("ROLE_ANALYST"),
                List.of("customer_data"), List.of("report.read"), "READ", "REPORT", true)).orElseThrow();

        assertThat(snapshot.getForbiddenResourceFamilies()).containsExactly("ACCOUNT");
        assertThat(snapshot.getForbiddenActionFamilies()).containsExactly("DELETE");
    }

    @Test
    @DisplayName("collect records denied history as negative scope evidence")
    void collect_recordsDeniedHistoryAsNegativeScopeEvidence() {
        collect(event(
                LocalDateTime.of(2026, 3, 26, 9, 0),
                List.of("ROLE_ANALYST"),
                List.of("customer_data"),
                List.of("report.read"),
                "READ",
                "REPORT",
                true));
        collect(event(
                LocalDateTime.of(2026, 3, 26, 9, 30),
                List.of("ROLE_ANALYST"),
                List.of("customer_data"),
                List.of("report.read"),
                "DELETE",
                "ACCOUNT",
                false));

        RoleScopeSnapshot snapshot = collect(event(
                        LocalDateTime.of(2026, 3, 26, 10, 0),
                        List.of("ROLE_ANALYST"),
                        List.of("customer_data"),
                        List.of("report.read"),
                        "READ",
                        "REPORT",
                        true))
                .orElseThrow();

        assertThat(snapshot.getForbiddenResourceFamilies()).containsExactly("ACCOUNT");
        assertThat(snapshot.getForbiddenActionFamilies()).containsExactly("DELETE");
        assertThat(snapshot.getTrustProfile().getQualityWarnings())
                .anyMatch(value -> value.contains("Forbidden families reflect observed denied scope"));
    }

    @Test
    @DisplayName("a business approval's decision age does not date the permission change (W2-9)")
    void collect_doesNotDateAnElevationByTheApprovalDecisionAge() {
        SecurityEvent elevated = event(
                LocalDateTime.of(2026, 3, 26, 9, 20),
                List.of("ROLE_ANALYST"),
                List.of("customer_data"),
                List.of("report.read"),
                "READ",
                "REPORT",
                true);
        elevated.addMetadata("temporaryElevation", true);
        elevated.addMetadata("temporaryElevationReason", "Emergency customer export review");
        elevated.addMetadata("approvalRequired", true);
        elevated.addMetadata("approvalStatus", "APPROVED");
        elevated.addMetadata("approvalDecisionAgeMinutes", 10);

        RoleScopeSnapshot snapshot = collect(elevated).orElseThrow();

        // The elevation was declared with this request; ten minutes is when the approval was decided.
        assertThat(snapshot.getElevationWindowSummary()).contains(": 0 minutes elapsed");
        // A stated elevation age still dates it.
        SecurityEvent dated = event(
                LocalDateTime.of(2026, 3, 26, 9, 40),
                List.of("ROLE_ANALYST"),
                List.of("customer_data"),
                List.of("report.read"),
                "READ",
                "REPORT",
                true);
        dated.addMetadata("temporaryElevation", true);
        dated.addMetadata("temporaryElevationReason", "Emergency customer export review");
        dated.addMetadata("elevationAgeMinutes", 7);
        assertThat(collect(dated).orElseThrow().getElevationWindowSummary()).contains(": 7 minutes elapsed");
    }

    @Test
    @DisplayName("collect detects authorization scope change and elevated window from explicit temporary elevation")
    void collect_detectsAuthorizationScopeChangeAndElevatedWindow() {
        collect(event(
                LocalDateTime.of(2026, 3, 26, 9, 0),
                List.of("ROLE_ANALYST"),
                List.of("customer_data"),
                List.of("report.read"),
                "READ",
                "REPORT",
                true));

        SecurityEvent changed = event(
                LocalDateTime.of(2026, 3, 26, 9, 20),
                List.of("ROLE_ANALYST", "ROLE_EXPORT_REVIEWER"),
                List.of("customer_data", "export"),
                List.of("report.read", "report.export"),
                "EXPORT",
                "REPORT",
                true);
        changed.addMetadata("temporaryElevation", true);
        changed.addMetadata("temporaryElevationReason", "Emergency customer export review");
        changed.addMetadata("approvalRequired", true);
        changed.addMetadata("approvalStatus", "APPROVED");
        changed.addMetadata("approvalDecisionAgeMinutes", 10);

        RoleScopeSnapshot snapshot = collect(changed).orElseThrow();

        assertThat(snapshot.getRecentPermissionChanges()).isNotEmpty();
        assertThat(snapshot.getTemporaryElevation()).isTrue();
        assertThat(snapshot.getElevatedPrivilegeWindowActive()).isTrue();
        assertThat(snapshot.getTemporaryElevationReason()).contains("Emergency customer export review");
        // The approval's decision age is not the permission change's age (W2-9): the change is the one just seen.
        assertThat(snapshot.getElevationWindowSummary()).contains(": 0 minutes elapsed")
                .doesNotContain("10 minutes elapsed");
    }

    @Test
    @DisplayName("collect treats reordered authorization scope values as the same scope")
    void collect_treatsReorderedAuthorizationScopeValuesAsSameScope() {
        collect(event(
                LocalDateTime.of(2026, 3, 26, 9, 0),
                List.of("ROLE_ANALYST", "ROLE_REVIEWER"),
                List.of("customer_data", "reporting"),
                List.of("report.read", "report.review"),
                "READ",
                "REPORT",
                true));

        RoleScopeSnapshot snapshot = collect(event(
                LocalDateTime.of(2026, 3, 26, 9, 20),
                List.of("ROLE_REVIEWER", "ROLE_ANALYST"),
                List.of("reporting", "customer_data"),
                List.of("report.review", "report.read"),
                "READ",
                "REPORT",
                true)).orElseThrow();

        assertThat(snapshot.getRecentPermissionChanges()).isEmpty();
        assertThat(snapshot.getTemporaryElevation()).isNull();
        assertThat(snapshot.getElevatedPrivilegeWindowActive()).isFalse();
    }

    @Test
    @DisplayName("collect keeps a protected method declared privileged out of the requester's authorization scope")
    void collect_keepsAMethodDeclaredPrivilegedOutOfTheAuthorizationScope() {
        collect(event(
                LocalDateTime.of(2026, 3, 26, 9, 0),
                List.of("ROLE_ADMIN"),
                List.of(),
                List.of("role.grant"),
                "READ",
                "PROJECT_ACCESS",
                true));
        SecurityEvent grant = event(
                LocalDateTime.of(2026, 3, 26, 9, 20),
                List.of("ROLE_ADMIN"),
                List.of(),
                List.of("role.grant"),
                "ADMIN",
                "PROJECT_ACCESS",
                true);
        grant.addMetadata("protectablePrivileged", true);

        RoleScopeSnapshot snapshot = collect(grant).orElseThrow();

        // P3 gate: calling a privileged method changes no permission of the requester and opens no elevation window.
        assertThat(snapshot.getRecentPermissionChanges()).isEmpty();
        assertThat(snapshot.getTemporaryElevation()).isNull();
        assertThat(snapshot.getElevatedPrivilegeWindowActive()).isFalse();
    }

    @Test
    @DisplayName("a refused read of one resource family keeps a read of another resource family out of denied scope")
    void collect_comparesDeniedScopeByRefusedPair() {
        collect(peerEvent(LocalDateTime.of(2026, 3, 26, 9, 0),
                List.of("ROLE_ENGINEER"), List.of("engineering"), List.of("document.read"), "READ", "DOCUMENT", true));
        collect(event(LocalDateTime.of(2026, 3, 26, 9, 30),
                List.of("ROLE_ENGINEER"), List.of("engineering"), List.of("document.read"), "READ", "CUSTOMER", false));

        RoleScopeSnapshot snapshot = collect(event(LocalDateTime.of(2026, 3, 26, 10, 0),
                List.of("ROLE_ENGINEER"), List.of("engineering"), List.of("document.read"), "READ", "DOCUMENT", true))
                .orElseThrow();

        assertThat(snapshot.getForbiddenResourceFamilies()).containsExactly("CUSTOMER");
        assertThat(snapshot.getForbiddenActionFamilies()).containsExactly("READ");
        assertThat(snapshot.getCurrentResourceFamilyInDeniedScope()).isFalse();
        assertThat(snapshot.getCurrentActionFamilyInDeniedScope()).isFalse();
        assertThat(snapshot.getResourceFamilyDrift()).isFalse();
        assertThat(snapshot.getActionFamilyDrift()).isFalse();
    }

    @Test
    @DisplayName("the refused pair itself is in denied scope in both dimensions")
    void collect_putsTheRefusedPairInDeniedScope() {
        collect(peerEvent(LocalDateTime.of(2026, 3, 26, 9, 0),
                List.of("ROLE_ENGINEER"), List.of("engineering"), List.of("document.read"), "READ", "DOCUMENT", true));
        collect(event(LocalDateTime.of(2026, 3, 26, 9, 30),
                List.of("ROLE_ENGINEER"), List.of("engineering"), List.of("document.read"), "READ", "CUSTOMER", false));

        RoleScopeSnapshot snapshot = collect(event(LocalDateTime.of(2026, 3, 26, 10, 0),
                List.of("ROLE_ENGINEER"), List.of("engineering"), List.of("document.read"), "READ", "CUSTOMER", true))
                .orElseThrow();

        assertThat(snapshot.getCurrentResourceFamilyInDeniedScope()).isTrue();
        assertThat(snapshot.getCurrentActionFamilyInDeniedScope()).isTrue();
        assertThat(snapshot.getResourceFamilyDrift()).isTrue();
        assertThat(snapshot.getActionFamilyDrift()).isTrue();
    }

    @Test
    @DisplayName("an unknown current resource family leaves denied scope unknown instead of matching the action alone")
    void collect_leavesDeniedScopeUnknownWhenTheResourceFamilyIsUnknown() {
        collect(event(LocalDateTime.of(2026, 3, 26, 9, 30),
                List.of("ROLE_ENGINEER"), List.of("engineering"), List.of("document.read"), "READ", "CUSTOMER", false));

        RoleScopeSnapshot snapshot = collect(event(LocalDateTime.of(2026, 3, 26, 10, 0),
                List.of("ROLE_ENGINEER"), List.of("engineering"), List.of("document.read"), "READ", "UNKNOWN", true))
                .orElseThrow();

        assertThat(snapshot.getForbiddenActionFamilies()).containsExactly("READ");
        assertThat(snapshot.getCurrentResourceFamilyInDeniedScope()).isNull();
        assertThat(snapshot.getCurrentActionFamilyInDeniedScope()).isNull();
        assertThat(snapshot.getActionFamilyDrift()).isNotEqualTo(Boolean.TRUE);
    }

    @Test
    @DisplayName("a family the host declares forbidden is in denied scope only in its own dimension")
    void collect_keepsADeclaredForbiddenFamilyInItsOwnDimension() {
        collect(peerEvent(LocalDateTime.of(2026, 3, 26, 9, 0),
                List.of("ROLE_ANALYST"), List.of("customer_data"), List.of("report.read"), "READ", "REPORT", true));
        SecurityEvent current = event(LocalDateTime.of(2026, 3, 26, 10, 0),
                List.of("ROLE_ANALYST"), List.of("customer_data"), List.of("report.read"), "DELETE", "REPORT", true);
        current.addMetadata("forbiddenActionFamilies", List.of("DELETE"));

        RoleScopeSnapshot snapshot = collect(current).orElseThrow();

        assertThat(snapshot.getCurrentActionFamilyInDeniedScope()).isTrue();
        assertThat(snapshot.getActionFamilyDrift()).isTrue();
        assertThat(snapshot.getCurrentResourceFamilyInDeniedScope()).isNull();
        assertThat(snapshot.getResourceFamilyDrift()).isFalse();
    }

    @Test
    @DisplayName("the current action family comes from the protected method, and earlier families and host hints read in one vocabulary (W2-1)")
    void collect_readsActionFamiliesInOneVocabulary() {
        collect(peerEvent(LocalDateTime.of(2026, 3, 26, 9, 0),
                List.of("ROLE_ANALYST"), List.of("customer_data"), List.of("report.read"), "CREATE", "REPORT", true));
        SecurityEvent export = event(LocalDateTime.of(2026, 3, 26, 10, 0),
                List.of("ROLE_ANALYST"), List.of("customer_data"), List.of("report.read"), null, "REPORT", true);
        export.addMetadata("httpMethod", "POST");
        export.addMetadata("protectableMethod", "io.contexa.example.BusinessOperations.exportDocuments");
        export.addMetadata("expectedActionFamilies", List.of("UPDATE"));

        RoleScopeSnapshot snapshot = collect(export).orElseThrow();

        assertThat(snapshot.getCurrentActionFamily()).isEqualTo("EXPORT");
        assertThat(snapshot.getExpectedActionFamilies()).containsExactly("WRITE");
        assertThat(snapshot.getActionFamilyDrift()).isTrue();
    }

    @Test
    @DisplayName("a family hint made only of class words is no scope category (W2-10)")
    void collect_passesOverAClassWordForTheScopeCategory() {
        collect(peerEvent(LocalDateTime.of(2026, 3, 26, 9, 0), List.of("ROLE_ANALYST"), List.of("customer_data"),
                List.of("report.read"), "READ", "CRITICAL", true));
        SecurityEvent current = event(LocalDateTime.of(2026, 3, 26, 9, 30), List.of("ROLE_ANALYST"),
                List.of("customer_data"), List.of("report.read"), "READ", "CRITICAL", true);
        current.addMetadata("resourceType", "REPORT");

        RoleScopeSnapshot snapshot = collect(current).orElseThrow();

        // The scope compares business categories; CRITICAL is a class, so the type names the category.
        assertThat(snapshot.getCurrentResourceFamily()).isEqualTo("REPORT");
        assertThat(snapshot.getExpectedResourceFamilies()).doesNotContain("CRITICAL");
    }

    @Test
    @DisplayName("the request's official category comes before the unprefixed hint (W2-11)")
    void collect_readsTheOfficialCategoryFirst() {
        SecurityEvent current = event(LocalDateTime.of(2026, 3, 26, 9, 30), List.of("ROLE_ANALYST"),
                List.of("customer_data"), List.of("report.read"), "READ", "REPORT", true);
        current.addMetadata("resourceCategory", "AUDIT_LOG");

        RoleScopeSnapshot snapshot = collect(current).orElseThrow();

        assertThat(snapshot.getCurrentResourceFamily()).isEqualTo("AUDIT_LOG");
    }

    private SecurityEvent event(
            LocalDateTime timestamp,
            List<String> effectiveRoles,
            List<String> scopeTags,
            List<String> permissions,
            String actionFamily,
            String resourceFamily,
            boolean granted) {
        return eventBy("alice", timestamp, effectiveRoles, scopeTags, permissions, actionFamily, resourceFamily, granted);
    }

    /** A request of another member of the same scope group (W5-10 D8). */
    private SecurityEvent peerEvent(
            LocalDateTime timestamp,
            List<String> effectiveRoles,
            List<String> scopeTags,
            List<String> permissions,
            String actionFamily,
            String resourceFamily,
            boolean granted) {
        return eventBy("bob", timestamp, effectiveRoles, scopeTags, permissions, actionFamily, resourceFamily, granted);
    }

    private SecurityEvent eventBy(
            String userId,
            LocalDateTime timestamp,
            List<String> effectiveRoles,
            List<String> scopeTags,
            List<String> permissions,
            String actionFamily,
            String resourceFamily,
            boolean granted) {
        SecurityEvent event = SecurityEvent.builder()
                .userId(userId)
                .timestamp(timestamp.atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("tenantId", "tenant-acme");
        event.addMetadata("effectiveRoles", effectiveRoles);
        event.addMetadata("scopeTags", scopeTags);
        event.addMetadata("effectivePermissions", permissions);
        event.addMetadata("currentActionFamily", actionFamily);
        event.addMetadata("currentResourceFamily", resourceFamily);
        event.addMetadata("policyId", "policy-1");
        event.addMetadata("policyVersion", "2026.03");
        event.addMetadata("granted", granted);
        event.addMetadata("authorizationEffect", granted ? "ALLOW" : "DENY");
        return event;
    }

    /** One request seen through to an enforced ALLOW, the way the pipeline records it (W2-7). */
    @Test
    @DisplayName("a role scope observation says which vocabulary its families are in; a v1 line still reads (W5-7)")
    void anObservationCarriesItsVocabularyAndAV1LineStillReads() {
        List<String[]> stored = new ArrayList<>();
        InMemorySecurityContextDataStore recording = new InMemorySecurityContextDataStore() {
            @Override
            public void addRoleScopeObservation(String tenantId, String scopeKey, String observation) {
                stored.add(new String[]{tenantId, scopeKey, observation});
                super.addRoleScopeObservation(tenantId, scopeKey, observation);
            }
        };
        DefaultRoleScopeCollector recordingCollector = new DefaultRoleScopeCollector(recording);
        SecurityEvent first = event(LocalDateTime.of(2026, 3, 26, 9, 0), List.of("ROLE_ANALYST"),
                List.of("customer_data"), List.of("report.read"), "READ", "REPORT", true);
        recordingCollector.collect(first);
        recordingCollector.recorder().commit(first, "ALLOW", true);

        assertThat(stored).hasSize(1);
        String[] fields = stored.get(0)[2].split("\\|", -1);
        // W5-10 D8: a v3 line keeps the member it is of.
        assertThat(fields[0]).isEqualTo("v3");
        assertThat(fields).hasSize(16);
        assertThat(new String(Base64.getUrlDecoder().decode(fields[14]), StandardCharsets.UTF_8))
                .isEqualTo(VocabularyVersion.CURRENT);
        assertThat(new String(Base64.getUrlDecoder().decode(fields[15]), StandardCharsets.UTF_8)).isEqualTo("alice");

        InMemorySecurityContextDataStore older = new InMemorySecurityContextDataStore();
        older.addRoleScopeObservation(stored.get(0)[0], stored.get(0)[1],
                "v1|" + String.join("|", Arrays.copyOfRange(fields, 1, 14)));
        RoleScopeSnapshot snapshot = new DefaultRoleScopeCollector(older).collect(event(
                        LocalDateTime.of(2026, 3, 26, 10, 0), List.of("ROLE_ANALYST"), List.of("customer_data"),
                        List.of("report.read"), "READ", "REPORT", true))
                .orElseThrow();
        // A line stored before the member was kept reads, but whose it is is not known: it is left out of the
        // group's usual scope (W5-10 D8). The same observation of another member is part of it.
        assertThat(snapshot.getExpectedResourceFamilies()).isEmpty();
        InMemorySecurityContextDataStore peers = new InMemorySecurityContextDataStore();
        peers.addRoleScopeObservation(stored.get(0)[0], stored.get(0)[1], String.join("|",
                Arrays.copyOfRange(fields, 0, 15)) + "|"
                + Base64.getUrlEncoder().withoutPadding().encodeToString("bob".getBytes(StandardCharsets.UTF_8)));
        RoleScopeSnapshot ofPeers = new DefaultRoleScopeCollector(peers).collect(event(
                        LocalDateTime.of(2026, 3, 26, 10, 0), List.of("ROLE_ANALYST"), List.of("customer_data"),
                        List.of("report.read"), "READ", "REPORT", true))
                .orElseThrow();
        assertThat(ofPeers.getExpectedResourceFamilies()).containsExactly("REPORT");
        assertThat(ofPeers.getPeerCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("the scope group's usual scope is its other members', and their number is kept (W5-10 D8)")
    void theUsualScopeIsTheOtherMembersAndTheirNumberIsKept() {
        collect(eventBy("alice", LocalDateTime.of(2026, 3, 26, 9, 0), List.of("ROLE_ANALYST"),
                List.of("customer_data"), List.of("report.read"), "EXPORT", "CUSTOMER", true));
        collect(eventBy("bob", LocalDateTime.of(2026, 3, 26, 9, 10), List.of("ROLE_ANALYST"),
                List.of("customer_data"), List.of("report.read"), "READ", "REPORT", true));
        collect(eventBy("carol", LocalDateTime.of(2026, 3, 26, 9, 20), List.of("ROLE_ANALYST"),
                List.of("customer_data"), List.of("report.read"), "READ", "REPORT", true));

        RoleScopeSnapshot snapshot = collect(event(LocalDateTime.of(2026, 3, 26, 10, 0), List.of("ROLE_ANALYST"),
                List.of("customer_data"), List.of("report.read"), "READ", "REPORT", true)).orElseThrow();

        // Alice's own export is not part of what her group usually does.
        assertThat(snapshot.getExpectedActionFamilies()).containsExactly("READ");
        assertThat(snapshot.getExpectedResourceFamilies()).containsExactly("REPORT");
        assertThat(snapshot.getPeerCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("a user alone in the scope group has no usual scope from it (W5-10 D8)")
    void aUserAloneInTheScopeGroupHasNoUsualScope() {
        collect(event(LocalDateTime.of(2026, 3, 26, 9, 0), List.of("ROLE_ANALYST"), List.of("customer_data"),
                List.of("report.read"), "READ", "REPORT", true));

        RoleScopeSnapshot snapshot = collect(event(LocalDateTime.of(2026, 3, 26, 10, 0), List.of("ROLE_ANALYST"),
                List.of("customer_data"), List.of("report.read"), "EXPORT", "REPORT", true)).orElseThrow();

        assertThat(snapshot.getExpectedActionFamilies()).isEmpty();
        assertThat(snapshot.getPeerCount()).isZero();
    }

    private Optional<RoleScopeSnapshot> collect(SecurityEvent event) {
        Optional<RoleScopeSnapshot> snapshot = collector.collect(event);
        collector.recorder().commit(event, "ALLOW", true);
        return snapshot;
    }
}
