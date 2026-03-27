package io.contexa.contexacommon.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationDetails;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationToken;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityContextStampResolversTest {

    private final SecurityContextAuthenticationStampResolver authenticationStampResolver = new SecurityContextAuthenticationStampResolver();
    private final SecurityContextAuthorizationStampResolver authorizationStampResolver = new SecurityContextAuthorizationStampResolver();

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void authenticationResolverShouldExtractRichContextFromPrincipalAndDetails() {
        Instant authenticationTime = Instant.parse("2026-03-23T10:15:30Z");
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                new CustomPrincipal("alice", "Alice Kim", "WORKFORCE", "tenant-acme", "finance"),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("REPORT_EXPORT"))
        );
        authentication.setDetails(Map.of(
                "authenticationType", "BIOMETRIC",
                "authenticationAssurance", "VERY_HIGH",
                "mfaVerified", true,
                "authenticatedAt", authenticationTime
        ));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthenticationStamp stamp = authenticationStampResolver.resolve(
                null,
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                new BridgeProperties()
        ).orElseThrow();

        assertThat(stamp.principalId()).isEqualTo("alice");
        assertThat(stamp.displayName()).isEqualTo("Alice Kim");
        assertThat(stamp.principalType()).isEqualTo("WORKFORCE");
        assertThat(stamp.authenticationType()).isEqualTo("BIOMETRIC");
        assertThat(stamp.authenticationAssurance()).isEqualTo("VERY_HIGH");
        assertThat(stamp.mfaCompleted()).isTrue();
        assertThat(stamp.authenticationTime()).isEqualTo(authenticationTime);
        assertThat(stamp.authorities()).contains("ROLE_USER", "REPORT_EXPORT");
        assertThat(stamp.attributes()).containsEntry("organizationId", "tenant-acme");
        assertThat(stamp.attributes()).containsEntry("department", "finance");
    }

    @Test
    void authenticationResolverShouldSupportConfiguredSecurityContextFieldNames() {
        BridgeProperties properties = new BridgeProperties();
        properties.getAuthentication().getSecurityContext().setDisplayNameKeys(List.of("personName"));
        properties.getAuthentication().getSecurityContext().setPrincipalTypeKeys(List.of("kind"));
        properties.getAuthentication().getSecurityContext().setAuthenticationTypeKeys(List.of("factor"));
        properties.getAuthentication().getSecurityContext().setAuthenticationAssuranceKeys(List.of("assuranceLevel"));
        properties.getAuthentication().getSecurityContext().setMfaKeys(List.of("verifiedMfa"));
        properties.getAuthentication().getSecurityContext().setAuthTimeKeys(List.of("signedAt"));
        properties.getAuthentication().getSecurityContext().setAttributeKeys(List.of("tenantCode", "division"));

        Instant signedAt = Instant.parse("2026-03-23T11:20:00Z");
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                new CustomMappedPrincipal("alice", "Alice Kim", "PARTNER", "tenant-acme", "ops"),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        authentication.setDetails(Map.of(
                "factor", "PATTERN",
                "assuranceLevel", "MEDIUM",
                "verifiedMfa", true,
                "signedAt", signedAt
        ));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthenticationStamp stamp = authenticationStampResolver.resolve(
                null,
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                properties
        ).orElseThrow();

        assertThat(stamp.displayName()).isEqualTo("Alice Kim");
        assertThat(stamp.principalType()).isEqualTo("PARTNER");
        assertThat(stamp.authenticationType()).isEqualTo("PATTERN");
        assertThat(stamp.authenticationAssurance()).isEqualTo("MEDIUM");
        assertThat(stamp.mfaCompleted()).isTrue();
        assertThat(stamp.authenticationTime()).isEqualTo(signedAt);
        assertThat(stamp.attributes()).containsEntry("tenantCode", "tenant-acme");
        assertThat(stamp.attributes()).containsEntry("division", "ops");
    }

    @Test
    void authorizationResolverShouldExtractEffectScopeAndPrivilegesFromSecurityContextDetails() {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                new CustomPrincipal("alice", "Alice Kim", "WORKFORCE", "tenant-acme", "finance"),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("REPORT_EXPORT"))
        );
        authentication.setDetails(Map.of(
                "authorizationEffect", "ALLOW",
                "privileged", true,
                "policyId", "policy-1",
                "policyVersion", "v2",
                "scopeTags", List.of("customer_data", "export"),
                "effectiveRoles", List.of("ROLE_FINANCE"),
                "effectiveAuthorities", List.of("REPORT_EXPORT", "REPORT_APPROVE")
        ));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthorizationStamp stamp = authorizationStampResolver.resolve(
                null,
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                new BridgeProperties()
        ).orElseThrow();

        assertThat(stamp.effect()).isEqualTo(AuthorizationEffect.ALLOW);
        assertThat(stamp.privileged()).isTrue();
        assertThat(stamp.policyId()).isEqualTo("policy-1");
        assertThat(stamp.policyVersion()).isEqualTo("v2");
        assertThat(stamp.scopeTags()).contains("customer_data", "export");
        assertThat(stamp.effectiveRoles()).contains("ROLE_FINANCE", "ROLE_USER");
        assertThat(stamp.effectiveAuthorities()).contains("REPORT_EXPORT", "REPORT_APPROVE", "ROLE_USER");
        assertThat(stamp.decisionSource()).isEqualTo("SECURITY_CONTEXT");
    }

    @Test
    void authorizationResolverShouldSupportConfiguredSecurityContextFieldNames() {
        BridgeProperties properties = new BridgeProperties();
        properties.getAuthorization().getSecurityContext().setAuthorizationEffectKeys(List.of("authzDecision"));
        properties.getAuthorization().getSecurityContext().setPrivilegedKeys(List.of("elevated"));
        properties.getAuthorization().getSecurityContext().setPolicyIdKeys(List.of("policyRef"));
        properties.getAuthorization().getSecurityContext().setPolicyVersionKeys(List.of("policyRevision"));
        properties.getAuthorization().getSecurityContext().setScopeTagKeys(List.of("grants"));
        properties.getAuthorization().getSecurityContext().setRoleKeys(List.of("grantedRoles"));
        properties.getAuthorization().getSecurityContext().setAuthorityKeys(List.of("grantedPerms"));
        properties.getAuthorization().getSecurityContext().setAttributeKeys(List.of("authzDecision", "elevated", "policyRef", "grants", "grantedRoles", "grantedPerms"));

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                new CustomMappedPrincipal("alice", "Alice Kim", "PARTNER", "tenant-acme", "ops"),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("REPORT_EXPORT"))
        );
        authentication.setDetails(Map.of(
                "authzDecision", "ALLOW",
                "elevated", true,
                "policyRef", "policy-x",
                "policyRevision", "rev-7",
                "grants", List.of("finance_data"),
                "grantedRoles", List.of("ROLE_CUSTOM"),
                "grantedPerms", List.of("REPORT_APPROVE")
        ));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthorizationStamp stamp = authorizationStampResolver.resolve(
                null,
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                properties
        ).orElseThrow();

        assertThat(stamp.effect()).isEqualTo(AuthorizationEffect.ALLOW);
        assertThat(stamp.privileged()).isTrue();
        assertThat(stamp.policyId()).isEqualTo("policy-x");
        assertThat(stamp.policyVersion()).isEqualTo("rev-7");
        assertThat(stamp.scopeTags()).contains("finance_data");
        assertThat(stamp.effectiveRoles()).contains("ROLE_CUSTOM", "ROLE_USER");
        assertThat(stamp.effectiveAuthorities()).contains("REPORT_APPROVE", "REPORT_EXPORT", "ROLE_USER");
    }

    @Test
    void authenticationResolverShouldNotDeriveAssuranceFromMfaPresenceAlone() {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                new CustomPrincipal("alice", "Alice Kim", "WORKFORCE", "tenant-acme", "finance"),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        authentication.setDetails(Map.of("mfaVerified", true));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthenticationStamp stamp = authenticationStampResolver.resolve(
                null,
                new RequestContextSnapshot("/reports/view", "GET", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/view", null, false, Instant.now()),
                new BridgeProperties()
        ).orElseThrow();

        assertThat(stamp.mfaCompleted()).isTrue();
        assertThat(stamp.authenticationAssurance()).isNull();
        assertThat(stamp.attributes()).containsEntry("authenticationAssuranceEvidenceState", "UNAVAILABLE");
    }

    @Test
    void authorizationResolverShouldKeepPrivilegedNullWhenOnlyAuthorityNamesSuggestElevation() {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                new CustomPrincipal("alice", "Alice Kim", "WORKFORCE", "tenant-acme", "finance"),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("REPORT_EXPORT"))
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthorizationStamp stamp = authorizationStampResolver.resolve(
                null,
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                new BridgeProperties()
        ).orElseThrow();

        assertThat(stamp.privileged()).isNull();
        assertThat(stamp.attributes()).containsEntry("authorizationPrivilegedEvidenceState", "UNAVAILABLE");
        assertThat(stamp.attributes()).containsEntry("privilegedAuthoritySignalPurpose", "HEURISTIC_HINT_ONLY");
        assertThat((List<String>) stamp.attributes().get("privilegedAuthoritySignals")).contains("ROLE_ADMIN");
    }

    @Test
    void resolversShouldReadBridgeAuthenticationDetailsFromSecurityContextToken() {
        BridgeAuthenticationDetails details = new BridgeAuthenticationDetails(
                "SESSION",
                "SECURITY_CONTEXT",
                "REQUEST_ATTRIBUTE",
                "AUTHORIZATION_CONTEXT",
                80,
                List.of("DELEGATION"),
                "Bridge resolved authentication and authorization context.",
                List.of("If delegated agents are used, propagate delegation metadata for the current request. Otherwise this gap can be ignored."),
                "MOBILE_BIOMETRIC",
                "HIGH",
                true,
                "tenant-acme",
                null,
                "finance",
                "ALLOW",
                true,
                "policy-1",
                "v3",
                List.of("customer_data"),
                List.of("ROLE_FINANCE"),
                List.of("REPORT_EXPORT"),
                true,
                "agent-1",
                "objective-1",
                "Export report",
                List.of("EXPORT"),
                List.of("report:monthly"),
                true,
                false,
                77L,
                "brg_sync_user",
                "brg_subject_key",
                "alice",
                true,
                true
        );
        BridgeAuthenticationToken authentication = new BridgeAuthenticationToken(
                "alice",
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("REPORT_EXPORT")),
                details
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthenticationStamp authenticationStamp = authenticationStampResolver.resolve(
                null,
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                new BridgeProperties()
        ).orElseThrow();
        AuthorizationStamp authorizationStamp = authorizationStampResolver.resolve(
                null,
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                new BridgeProperties()
        ).orElseThrow();

        assertThat(authenticationStamp.authenticationType()).isEqualTo("MOBILE_BIOMETRIC");
        assertThat(authenticationStamp.authenticationAssurance()).isEqualTo("HIGH");
        assertThat(authenticationStamp.attributes()).containsEntry("organizationId", "tenant-acme");
        assertThat(authorizationStamp.effect()).isEqualTo(AuthorizationEffect.ALLOW);
        assertThat(authorizationStamp.scopeTags()).contains("customer_data");
        assertThat(authorizationStamp.effectiveRoles()).contains("ROLE_FINANCE", "ROLE_USER");
    }

    @Test
    void resolversShouldSupportPrivateAccessorsOnCustomSecurityContextObjects() {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                new PrivatePrincipal("alice", "Alice Private", "WORKFORCE"),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("REPORT_EXPORT"))
        );
        authentication.setDetails(new PrivateDetails(
                "PASSKEY",
                "VERY_HIGH",
                true,
                "ALLOW",
                true,
                List.of("finance_scope"),
                List.of("ROLE_FINANCE"),
                List.of("REPORT_APPROVE")
        ));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthenticationStamp authenticationStamp = authenticationStampResolver.resolve(
                null,
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                new BridgeProperties()
        ).orElseThrow();
        AuthorizationStamp authorizationStamp = authorizationStampResolver.resolve(
                null,
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                new BridgeProperties()
        ).orElseThrow();

        assertThat(authenticationStamp.principalId()).isEqualTo("alice");
        assertThat(authenticationStamp.displayName()).isEqualTo("Alice Private");
        assertThat(authenticationStamp.principalType()).isEqualTo("WORKFORCE");
        assertThat(authenticationStamp.authenticationType()).isEqualTo("PASSKEY");
        assertThat(authenticationStamp.authenticationAssurance()).isEqualTo("VERY_HIGH");
        assertThat(authenticationStamp.mfaCompleted()).isTrue();
        assertThat(authorizationStamp.effect()).isEqualTo(AuthorizationEffect.ALLOW);
        assertThat(authorizationStamp.scopeTags()).contains("finance_scope");
        assertThat(authorizationStamp.effectiveRoles()).contains("ROLE_FINANCE", "ROLE_USER");
        assertThat(authorizationStamp.effectiveAuthorities()).contains("REPORT_APPROVE", "REPORT_EXPORT", "ROLE_USER");
    }

    private static final class PrivatePrincipal {
        private final String userId;
        private final String displayName;
        private final String principalType;

        private PrivatePrincipal(String userId, String displayName, String principalType) {
            this.userId = userId;
            this.displayName = displayName;
            this.principalType = principalType;
        }

        private String userId() {
            return userId;
        }

        private String displayName() {
            return displayName;
        }

        private String principalType() {
            return principalType;
        }
    }

    private static final class PrivateDetails {
        private final String authenticationType;
        private final String authenticationAssurance;
        private final boolean mfaVerified;
        private final String authorizationEffect;
        private final boolean privileged;
        private final List<String> scopeTags;
        private final List<String> effectiveRoles;
        private final List<String> effectiveAuthorities;

        private PrivateDetails(
                String authenticationType,
                String authenticationAssurance,
                boolean mfaVerified,
                String authorizationEffect,
                boolean privileged,
                List<String> scopeTags,
                List<String> effectiveRoles,
                List<String> effectiveAuthorities) {
            this.authenticationType = authenticationType;
            this.authenticationAssurance = authenticationAssurance;
            this.mfaVerified = mfaVerified;
            this.authorizationEffect = authorizationEffect;
            this.privileged = privileged;
            this.scopeTags = scopeTags;
            this.effectiveRoles = effectiveRoles;
            this.effectiveAuthorities = effectiveAuthorities;
        }

        private String authenticationType() {
            return authenticationType;
        }

        private String authenticationAssurance() {
            return authenticationAssurance;
        }

        private boolean mfaVerified() {
            return mfaVerified;
        }

        private String authorizationEffect() {
            return authorizationEffect;
        }

        private boolean privileged() {
            return privileged;
        }

        private List<String> scopeTags() {
            return scopeTags;
        }

        private List<String> effectiveRoles() {
            return effectiveRoles;
        }

        private List<String> effectiveAuthorities() {
            return effectiveAuthorities;
        }
    }

    private record CustomPrincipal(
            String username,
            String displayName,
            String principalType,
            String organizationId,
            String department
    ) implements java.security.Principal {
        @Override
        public String getName() {
            return username;
        }
    }

    private record CustomMappedPrincipal(
            String username,
            String personName,
            String kind,
            String tenantCode,
            String division
    ) implements java.security.Principal {
        @Override
        public String getName() {
            return username;
        }
    }
}


