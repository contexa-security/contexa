package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.context.hardener.CanonicalSecurityContextHardener;

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
                .session(CanonicalSecurityContext.Session.builder()
                        .currentAccessHour(29)
                        .concurrentSessions(-2)
                        .passwordAgeDays(-9)
                        .build())
                .device(CanonicalSecurityContext.Device.builder()
                        .os(" windows ")
                        .osVersion(" 11 ")
                        .browser(" Chrome ")
                        .browserVersion(" 136 ")
                        .screenResolution(" 1920x1080 ")
                        .language(" ko-KR ")
                        .build())
                .location(CanonicalSecurityContext.Location.builder()
                        .country(" kr ")
                        .city(" Seoul ")
                        .ipBand(" 203.0.113.0/24 ")
                        .asn(" as64512 ")
                        .build())
                .intent(CanonicalSecurityContext.Intent.builder()
                        .missingReferer(true)
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
        assertThat(hardened.getSession().getCurrentAccessHour()).isEqualTo(23);
        assertThat(hardened.getSession().getConcurrentSessions()).isZero();
        assertThat(hardened.getSession().getPasswordAgeDays()).isZero();
        assertThat(hardened.getDevice().getOs()).isEqualTo("WINDOWS");
        assertThat(hardened.getDevice().getOsVersion()).isEqualTo("11");
        assertThat(hardened.getDevice().getBrowser()).isEqualTo("Chrome");
        assertThat(hardened.getDevice().getBrowserVersion()).isEqualTo("136");
        assertThat(hardened.getDevice().getScreenResolution()).isEqualTo("1920x1080");
        assertThat(hardened.getDevice().getLanguage()).isEqualTo("ko-KR");
        assertThat(hardened.getLocation().getCountry()).isEqualTo("KR");
        assertThat(hardened.getLocation().getCity()).isEqualTo("Seoul");
        assertThat(hardened.getLocation().getIpBand()).isEqualTo("203.0.113.0/24");
        assertThat(hardened.getLocation().getAsn()).isEqualTo("AS64512");
        assertThat(hardened.getIntent().getMissingReferer()).isTrue();
        assertThat(hardened.getResource().getResourceType()).isEqualTo("REPORT");
        assertThat(hardened.getResource().getSensitivity()).isEqualTo("HIGH");
        assertThat(hardened.getResource().getActionFamily()).isEqualTo("EXPORT");
        assertThat(hardened.getAuthorization().getScopeTags()).containsExactly("customer_data");
        assertThat(hardened.getObservedScope().getProfileSource()).isEqualTo("PROTECTABLE_ACCESS_HISTORY");
        assertThat(hardened.getObservedScope().getRecentDeniedAccessCount()).isZero();
        assertThat(hardened.getObservedScope().getFrequentResources()).containsExactly("/a");
    }
}