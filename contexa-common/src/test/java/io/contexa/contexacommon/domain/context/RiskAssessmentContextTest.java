package io.contexa.contexacommon.domain.context;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class RiskAssessmentContextTest {

    @Test
    @DisplayName("create factory sets userId, resourceIdentifier, and actionType")
    void create_shouldSetBasicFields() {
        RiskAssessmentContext ctx = RiskAssessmentContext.create("user-1", "resource-1", "READ");

        assertThat(ctx.getUserId()).isEqualTo("user-1");
        assertThat(ctx.getResourceIdentifier()).isEqualTo("resource-1");
        assertThat(ctx.getActionType()).isEqualTo("READ");
        assertThat(ctx.getDomainType()).isEqualTo("RISK_ASSESSMENT");
        assertThat(ctx.getContextId()).isNotNull();
    }

    @Test
    @DisplayName("createDetailed factory sets all detailed fields")
    void createDetailed_shouldSetAllDetailedFields() {
        List<String> roles = List.of("ADMIN", "USER");

        RiskAssessmentContext ctx = RiskAssessmentContext.createDetailed(
                "user-1", "John", "session-1",
                "resource-1", "WRITE",
                "10.0.0.1", roles
        );

        assertThat(ctx.getUserId()).isEqualTo("user-1");
        assertThat(ctx.getUserName()).isEqualTo("John");
        assertThat(ctx.getSessionId()).isEqualTo("session-1");
        assertThat(ctx.getResourceIdentifier()).isEqualTo("resource-1");
        assertThat(ctx.getActionType()).isEqualTo("WRITE");
        assertThat(ctx.getRemoteIp()).isEqualTo("10.0.0.1");
        assertThat(ctx.getUserRoles()).containsExactly("ADMIN", "USER");
    }

    @Test
    @DisplayName("createUrgent factory sets urgentReason in environmentAttributes")
    void createUrgent_shouldSetUrgentReason() {
        RiskAssessmentContext ctx = RiskAssessmentContext.createUrgent(
                "user-1", "resource-1", "DELETE", "emergency access"
        );

        assertThat(ctx.getUserId()).isEqualTo("user-1");
        assertThat(ctx.getEnvironmentAttributes()).containsEntry("urgentReason", "emergency access");
    }

    @Test
    @DisplayName("withHistoryContext returns this for chaining")
    void withHistoryContext_shouldReturnThisForChaining() {
        RiskAssessmentContext ctx = RiskAssessmentContext.create("user-1", "res-1", "READ");

        RiskAssessmentContext result = ctx.withHistoryContext("some history");

        assertThat(result).isSameAs(ctx);
        assertThat(result.getHistoryContext()).isEqualTo("some history");
    }

    @Test
    @DisplayName("withBehaviorMetrics returns this for chaining")
    void withBehaviorMetrics_shouldReturnThisForChaining() {
        RiskAssessmentContext ctx = RiskAssessmentContext.create("user-1", "res-1", "READ");
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("loginCount", 5);

        RiskAssessmentContext result = ctx.withBehaviorMetrics(metrics);

        assertThat(result).isSameAs(ctx);
        assertThat(result.getBehaviorMetrics()).containsEntry("loginCount", 5);
    }

    @Test
    @DisplayName("withEnvironmentAttribute returns this for chaining")
    void withEnvironmentAttribute_shouldReturnThisForChaining() {
        RiskAssessmentContext ctx = RiskAssessmentContext.create("user-1", "res-1", "READ");

        RiskAssessmentContext result = ctx.withEnvironmentAttribute("env", "production");

        assertThat(result).isSameAs(ctx);
        assertThat(result.getEnvironmentAttributes()).containsEntry("env", "production");
    }

    @Test
    @DisplayName("withEnvironmentAttribute initializes map if null")
    void withEnvironmentAttribute_shouldInitializeMapIfNull() {
        RiskAssessmentContext ctx = RiskAssessmentContext.create("user-1", "res-1", "READ");
        ctx.setEnvironmentAttributes(null);

        RiskAssessmentContext result = ctx.withEnvironmentAttribute("key", "value");

        assertThat(result.getEnvironmentAttributes()).isNotNull();
        assertThat(result.getEnvironmentAttributes()).containsEntry("key", "value");
    }

    @Test
    @DisplayName("calculateRiskComplexity sums all collection sizes")
    void calculateRiskComplexity_shouldSumAllCollectionSizes() {
        RiskAssessmentContext ctx = RiskAssessmentContext.create("user-1", "res-1", "READ");
        ctx.setUserRoles(List.of("ADMIN", "USER"));            // 2
        ctx.setUserGroups(List.of("GROUP_A"));                  // 1
        ctx.setUserPermissions(List.of("PERM_1", "PERM_2", "PERM_3")); // 3

        Map<String, Object> metrics = new HashMap<>();
        metrics.put("m1", 1);
        metrics.put("m2", 2);
        ctx.setBehaviorMetrics(metrics);                        // 2

        ctx.withEnvironmentAttribute("env", "prod");            // 1 (already has entries from create)

        int complexity = ctx.calculateRiskComplexity();

        // 2 + 1 + 3 + 2 + environmentAttributes.size()
        assertThat(complexity).isEqualTo(2 + 1 + 3 + 2 + ctx.getEnvironmentAttributes().size());
    }

    @Test
    @DisplayName("calculateRiskComplexity returns 0 when all collections are null")
    void calculateRiskComplexity_shouldReturnZeroWhenAllNull() {
        RiskAssessmentContext ctx = RiskAssessmentContext.create("user-1", "res-1", "READ");
        ctx.setUserRoles(null);
        ctx.setUserGroups(null);
        ctx.setUserPermissions(null);
        ctx.setBehaviorMetrics(null);
        ctx.setEnvironmentAttributes(null);

        assertThat(ctx.calculateRiskComplexity()).isEqualTo(0);
    }

    @Test
    @DisplayName("Builder chaining allows fluent configuration")
    void builderChaining_shouldAllowFluentConfiguration() {
        Map<String, Object> metrics = Map.of("score", 0.8);

        RiskAssessmentContext ctx = RiskAssessmentContext.create("user-1", "res-1", "WRITE")
                .withHistoryContext("past activity")
                .withBehaviorMetrics(new HashMap<>(metrics))
                .withEnvironmentAttribute("region", "us-east-1");

        assertThat(ctx.getHistoryContext()).isEqualTo("past activity");
        assertThat(ctx.getBehaviorMetrics()).containsEntry("score", 0.8);
        assertThat(ctx.getEnvironmentAttributes()).containsEntry("region", "us-east-1");
    }

    @Test
    @DisplayName("toString contains userId, resource, action, ip, and complexity")
    void toString_shouldContainExpectedFields() {
        RiskAssessmentContext ctx = RiskAssessmentContext.createDetailed(
                "user-1", "John", "session-1",
                "/api/data", "GET",
                "192.168.1.1", List.of("USER")
        );

        String str = ctx.toString();

        assertThat(str).contains("user-1");
        assertThat(str).contains("/api/data");
        assertThat(str).contains("GET");
        assertThat(str).contains("192.168.1.1");
    }

    @Test
    @DisplayName("Default constructor initializes empty maps")
    void defaultConstructor_shouldInitializeEmptyMaps() {
        RiskAssessmentContext ctx = new RiskAssessmentContext();

        assertThat(ctx.getBehaviorMetrics()).isNotNull().isEmpty();
        assertThat(ctx.getEnvironmentAttributes()).isNotNull().isEmpty();
    }
}
