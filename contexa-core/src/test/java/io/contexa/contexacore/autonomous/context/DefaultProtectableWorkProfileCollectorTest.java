package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

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
                .timestamp(LocalDateTime.of(2026, 3, 25, 9, 0))
                .build();

        assertThat(collector.collect(event)).isEmpty();
    }

    @Test
    @DisplayName("collect builds work profile from prior history without contaminating it with the current request")
    void collect_buildsProfileFromPriorHistoryWithoutCurrentRequestContamination() {
        collector.collect(event(
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

        ProtectableWorkProfileSnapshot snapshot = collector.collect(event(
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
        assertThat(snapshot.getWindowDays()).isEqualTo(7);
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
        assertThat(snapshot.getSummary()).contains("Frequent protectable resources /api/customer/list");
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
                .timestamp(LocalDateTime.of(2026, 3, 24, 9, 0))
                .description("GET missing-path")
                .build();
        first.addMetadata("tenantId", "tenant-acme");
        first.addMetadata("httpMethod", "GET");
        first.addMetadata("actionFamily", "READ");
        first.addMetadata("currentResourceFamily", "REPORT");
        first.addMetadata("resourceSensitivity", "HIGH");
        first.addMetadata("isProtectable", true);
        first.addMetadata("granted", true);

        ProtectableWorkProfileSnapshot snapshot = collector.collect(first).orElseThrow();

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
        collector.collect(event(
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
        collector.collect(event(
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
        collector.collect(event(
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

        ProtectableWorkProfileSnapshot snapshot = collector.collect(event(
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
                .timestamp(timestamp)
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
}
