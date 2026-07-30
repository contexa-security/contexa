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

import io.contexa.contexacore.autonomous.context.collector.DefaultRoleScopeCollector;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacore.autonomous.context.collector.RoleScopeSnapshot;

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
        collector.collect(event(
                LocalDateTime.of(2026, 3, 26, 9, 0),
                List.of("ROLE_ANALYST"),
                List.of("customer_data"),
                List.of("report.read"),
                "READ",
                "REPORT",
                true));

        RoleScopeSnapshot snapshot = collector.collect(event(
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
    @DisplayName("collect records denied history as negative scope evidence")
    void collect_recordsDeniedHistoryAsNegativeScopeEvidence() {
        collector.collect(event(
                LocalDateTime.of(2026, 3, 26, 9, 0),
                List.of("ROLE_ANALYST"),
                List.of("customer_data"),
                List.of("report.read"),
                "READ",
                "REPORT",
                true));
        collector.collect(event(
                LocalDateTime.of(2026, 3, 26, 9, 30),
                List.of("ROLE_ANALYST"),
                List.of("customer_data"),
                List.of("report.read"),
                "DELETE",
                "ACCOUNT",
                false));

        RoleScopeSnapshot snapshot = collector.collect(event(
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
    @DisplayName("collect detects authorization scope change and elevated window from explicit temporary elevation")
    void collect_detectsAuthorizationScopeChangeAndElevatedWindow() {
        collector.collect(event(
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

        RoleScopeSnapshot snapshot = collector.collect(changed).orElseThrow();

        assertThat(snapshot.getRecentPermissionChanges()).isNotEmpty();
        assertThat(snapshot.getTemporaryElevation()).isTrue();
        assertThat(snapshot.getElevatedPrivilegeWindowActive()).isTrue();
        assertThat(snapshot.getTemporaryElevationReason()).contains("Emergency customer export review");
        assertThat(snapshot.getElevationWindowSummary()).contains("0");
    }

    @Test
    @DisplayName("collect treats reordered authorization scope values as the same scope")
    void collect_treatsReorderedAuthorizationScopeValuesAsSameScope() {
        collector.collect(event(
                LocalDateTime.of(2026, 3, 26, 9, 0),
                List.of("ROLE_ANALYST", "ROLE_REVIEWER"),
                List.of("customer_data", "reporting"),
                List.of("report.read", "report.review"),
                "READ",
                "REPORT",
                true));

        RoleScopeSnapshot snapshot = collector.collect(event(
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
    private SecurityEvent event(
            LocalDateTime timestamp,
            List<String> effectiveRoles,
            List<String> scopeTags,
            List<String> permissions,
            String actionFamily,
            String resourceFamily,
            boolean granted) {
        SecurityEvent event = SecurityEvent.builder()
                .userId("alice")
                .timestamp(timestamp)
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
}
