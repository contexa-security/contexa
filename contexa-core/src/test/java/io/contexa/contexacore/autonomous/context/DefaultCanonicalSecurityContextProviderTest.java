package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultCanonicalSecurityContextProviderTest {

    @Test
    void resolveShouldNormalizeEventMetadataIntoCanonicalSecurityContext() {
        InMemoryResourceContextRegistry registry = new InMemoryResourceContextRegistry();
        registry.register(new ResourceContextDescriptor(
                "/api/customer/export",
                "REPORT",
                "Customer Export Report",
                "HIGH",
                List.of("ANALYST"),
                List.of("READ", "EXPORT"),
                true,
                true));

        DefaultCanonicalSecurityContextProvider provider =
                new DefaultCanonicalSecurityContextProvider(registry, new ContextCoverageEvaluator());

        SecurityEvent event = SecurityEvent.builder()
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("203.0.113.10")
                .userAgent("Mozilla/5.0")
                .timestamp(LocalDateTime.of(2026, 3, 23, 14, 0))
                .build();
        event.addMetadata("requestPath", "/api/customer/export");
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("organizationId", "tenant-acme");
        event.addMetadata("department", "finance");
        event.addMetadata("userRoles", "ANALYST,EXPORT_REVIEWER");
        event.addMetadata("effectivePermissions", List.of("report.read", "report.export"));
        event.addMetadata("scopeTags", List.of("customer_data", "export"));
        event.addMetadata("mfaVerified", true);
        event.addMetadata("failedLoginAttempts", 1);
        event.addMetadata("recentRequestCount", 7);
        event.addMetadata("bridgeCoverageLevel", "AUTHORIZATION_CONTEXT");
        event.addMetadata("bridgeCoverageScore", 80);
        event.addMetadata("bridgeCoverageSummary", "Bridge resolved authentication and authorization context for the current request.");
        event.addMetadata("bridgeRemediationHints", List.of("If delegated agents are used, propagate delegation metadata for the current request. Otherwise this gap can be ignored."));
        event.addMetadata("bridgeMissingContexts", List.of("DELEGATION"));
        event.addMetadata("bridgeAuthenticationSource", "SECURITY_CONTEXT");
        event.addMetadata("bridgeAuthorizationSource", "HEADER");

        CanonicalSecurityContext context = provider.resolve(event).orElseThrow();

        assertThat(context.getActor().getUserId()).isEqualTo("alice");
        assertThat(context.getActor().getOrganizationId()).isEqualTo("tenant-acme");
        assertThat(context.getAuthorization().getEffectiveRoles()).contains("ANALYST", "EXPORT_REVIEWER");
        assertThat(context.getAuthorization().getEffectivePermissions()).contains("report.read", "report.export");
        assertThat(context.getResource().getBusinessLabel()).isEqualTo("Customer Export Report");
        assertThat(context.getResource().getSensitivity()).isEqualTo("HIGH");
        assertThat(context.getBridge()).isNotNull();
        assertThat(context.getBridge().getCoverageLevel()).isEqualTo("AUTHORIZATION_CONTEXT");
        assertThat(context.getBridge().getSummary()).contains("authentication and authorization context");
        assertThat(context.getBridge().getRemediationHints()).hasSize(1);
        assertThat(context.getBridge().getAuthenticationSource()).isEqualTo("SECURITY_CONTEXT");
        assertThat(context.getBridge().getAuthorizationSource()).isEqualTo("HEADER");
        assertThat(context.getBridge().getMissingContexts()).contains("DELEGATION");
        assertThat(context.getCoverage().level()).isEqualTo(ContextCoverageLevel.BUSINESS_AWARE);
    }

    @Test
    void resolveShouldApplyExternalProvidersAndObservedScopeInference() {
        DefaultCanonicalSecurityContextProvider provider = new DefaultCanonicalSecurityContextProvider(
                new InMemoryResourceContextRegistry(),
                new ContextCoverageEvaluator(),
                List.of((event, context) -> {
                    if (context.getActor() == null) {
                        context.setActor(new CanonicalSecurityContext.Actor());
                    }
                    context.getActor().setPrincipalType("EXTERNAL_WORKFORCE");
                }),
                List.of((event, context) -> {
                    if (context.getAuthorization() == null) {
                        context.setAuthorization(new CanonicalSecurityContext.Authorization());
                    }
                    context.getAuthorization().setScopeTags(List.of("finance_ops", "export"));
                }),
                List.of((event, context) -> {
                    if (context.getActor() == null) {
                        context.setActor(new CanonicalSecurityContext.Actor());
                    }
                    context.getActor().setDepartment("finance");
                }),
                List.of(),
                new MetadataObservedScopeInferenceService());

        SecurityEvent event = SecurityEvent.builder()
                .userId("alice")
                .sessionId("session-1")
                .build();
        event.addMetadata("requestPath", "/api/customer/export");
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("protectableAccessHistory", List.of(
                java.util.Map.of("resourceId", "/api/customer/list", "actionFamily", "READ", "result", "ALLOWED"),
                java.util.Map.of("resourceId", "/api/customer/list", "actionFamily", "READ", "result", "ALLOWED"),
                java.util.Map.of("resourceId", "/api/customer/export", "actionFamily", "EXPORT", "result", "DENIED", "isSensitiveResource", true)));

        CanonicalSecurityContext context = provider.resolve(event).orElseThrow();

        assertThat(context.getActor().getPrincipalType()).isEqualTo("EXTERNAL_WORKFORCE");
        assertThat(context.getActor().getDepartment()).isEqualTo("finance");
        assertThat(context.getAuthorization().getScopeTags()).contains("finance_ops", "export");
        assertThat(context.getObservedScope()).isNotNull();
        assertThat(context.getObservedScope().getFrequentResources()).contains("/api/customer/list");
        assertThat(context.getObservedScope().getRecentDeniedAccessCount()).isEqualTo(1);
    }

    @Test
    void resolveShouldApplyCanonicalHardeningAfterProviderContribution() {
        DefaultCanonicalSecurityContextProvider provider = new DefaultCanonicalSecurityContextProvider(
                new InMemoryResourceContextRegistry(),
                new ContextCoverageEvaluator(),
                List.of((event, context) -> {
                    if (context.getActor() == null) {
                        context.setActor(new CanonicalSecurityContext.Actor());
                    }
                    context.getActor().setPrincipalType(" employee ");
                    context.getActor().setRoleSet(List.of("ANALYST", " ANALYST ", ""));
                }),
                List.of((event, context) -> {
                    if (context.getAuthorization() == null) {
                        context.setAuthorization(new CanonicalSecurityContext.Authorization());
                    }
                    context.getAuthorization().setScopeTags(List.of(" finance_ops ", "", "finance_ops"));
                }),
                List.of(),
                List.of(),
                new MetadataObservedScopeInferenceService(),
                new CanonicalSecurityContextHardener());

        SecurityEvent event = SecurityEvent.builder()
                .userId(" alice ")
                .sessionId(" session-1 ")
                .build();
        event.addMetadata("requestPath", " /api/customer/export ");

        CanonicalSecurityContext context = provider.resolve(event).orElseThrow();

        assertThat(context.getActor().getUserId()).isEqualTo("alice");
        assertThat(context.getActor().getPrincipalType()).isEqualTo("EMPLOYEE");
        assertThat(context.getActor().getRoleSet()).containsExactly("ANALYST");
        assertThat(context.getAuthorization().getScopeTags()).containsExactly("finance_ops");
        assertThat(context.getSession().getSessionId()).isEqualTo("session-1");
        assertThat(context.getResource().getResourceId()).isEqualTo("/api/customer/export");
    }
}
