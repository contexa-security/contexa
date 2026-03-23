package io.contexa.contexacore.autonomous.context;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CanonicalSecurityContextHardenerTest {

    @Test
    void hardenShouldTrimNormalizeAndDeduplicateCanonicalFields() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId(" alice ")
                        .organizationId(" ")
                        .principalType(" employee ")
                        .roleSet(List.of("ANALYST", " ANALYST ", ""))
                        .authoritySet(List.of("report.read", " report.read "))
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceType(" report ")
                        .sensitivity(" high ")
                        .actionFamily(" export ")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ANALYST", ""))
                        .scopeTags(List.of("customer_data", " customer_data "))
                        .build())
                .observedScope(CanonicalSecurityContext.ObservedScope.builder()
                        .profileSource(" protectable_access_history ")
                        .recentDeniedAccessCount(-1)
                        .frequentResources(List.of("/a", " /a ", ""))
                        .build())
                .build();

        CanonicalSecurityContext hardened = new CanonicalSecurityContextHardener().harden(context);

        assertThat(hardened.getActor().getUserId()).isEqualTo("alice");
        assertThat(hardened.getActor().getOrganizationId()).isNull();
        assertThat(hardened.getActor().getPrincipalType()).isEqualTo("EMPLOYEE");
        assertThat(hardened.getActor().getRoleSet()).containsExactly("ANALYST");
        assertThat(hardened.getActor().getAuthoritySet()).containsExactly("report.read");
        assertThat(hardened.getResource().getResourceType()).isEqualTo("REPORT");
        assertThat(hardened.getResource().getSensitivity()).isEqualTo("HIGH");
        assertThat(hardened.getResource().getActionFamily()).isEqualTo("EXPORT");
        assertThat(hardened.getAuthorization().getScopeTags()).containsExactly("customer_data");
        assertThat(hardened.getObservedScope().getProfileSource()).isEqualTo("PROTECTABLE_ACCESS_HISTORY");
        assertThat(hardened.getObservedScope().getRecentDeniedAccessCount()).isZero();
        assertThat(hardened.getObservedScope().getFrequentResources()).containsExactly("/a");
    }
}
