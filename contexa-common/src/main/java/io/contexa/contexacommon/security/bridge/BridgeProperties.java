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
package io.contexa.contexacommon.security.bridge;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.operating.OperatingBehaviour;
import lombok.AccessLevel;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
@ConfigurationProperties(prefix = "contexa.bridge")
public class BridgeProperties implements EnvironmentAware {

    private boolean enabled = true;

    private SecurityOwnershipMode ownership = SecurityOwnershipMode.HOST_OWNED;

    /**
     * The mode the application runs Contexa in, read from what {@code @EnableAISecurity} published; not a setting of the
     * bridge. Without an environment it is the mode that goes with the ownership.
     */
    @Getter(AccessLevel.NONE)
    @Setter(AccessLevel.NONE)
    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    private transient SecurityMode operatingMode;

    private boolean populateSecurityContext = true;

    @NestedConfigurationProperty
    private Authentication authentication = new Authentication();

    @NestedConfigurationProperty
    private Authorization authorization = new Authorization();

    @NestedConfigurationProperty
    private Delegation delegation = new Delegation();

    @NestedConfigurationProperty
    private Sync sync = new Sync();

    @NestedConfigurationProperty
    private Network network = new Network();

    @NestedConfigurationProperty
    private StepUp stepUp = new StepUp();

    /**
     * bridge v2: where the identity of a request comes from, tried in this order; a source that has nothing for the
     * request is skipped. {@code spring-security} reads the signed-in user of the application's Spring Security,
     * {@code resolver} asks the application's {@code ContexaSubjectResolver} bean, {@code request-attribute} reads the
     * {@code ContexaSubject} the application put under {@code ctxa.subject}.
     */
    private List<String> identitySources = List.of("spring-security", "resolver", "request-attribute");

    /**
     * bridge v2: where the mail address of a Spring Security user comes from, tried in this order: {@code claim:<name>}
     * reads a claim of the user's token or OAuth2 login, {@code provider} asks the application's
     * {@code BridgeUserEmailProvider} bean.
     */
    private List<String> emailSources = List.of("claim:email", "provider");

    @NestedConfigurationProperty
    private Resolver resolver = new Resolver();

    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.operatingMode = ContexaOperatingProfile.resolve(environment).mode();
    }

    public OperatingBehaviour operatingBehaviour() {
        SecurityMode mode = operatingMode != null ? operatingMode
                : ownership == SecurityOwnershipMode.CONTEXA_OWNED ? SecurityMode.FULL : SecurityMode.SANDBOX;
        return OperatingBehaviour.of(mode, ownership);
    }

    @Data
    public static class Authentication {
        private boolean preferSecurityContext = true;

        @NestedConfigurationProperty
        private SecurityContext securityContext = new SecurityContext();

        @Data
        public static class SecurityContext {
            private boolean enabled = true;
            private List<String> displayNameKeys = List.of("displayName", "name", "fullName", "userName", "username", "preferred_username");
            private List<String> principalTypeKeys = List.of("principalType", "userType", "actorType", "token_use");
            private List<String> authenticationTypeKeys = List.of("authenticationType", "authMethod", "loginMethod", "method", "factorType");
            private List<String> authenticationAssuranceKeys = List.of("authenticationAssurance", "authLevel", "loa", "acr");
            private List<String> mfaKeys = List.of("mfa", "mfaVerified", "mfaCompleted", "secondFactorVerified");
            /** Token issue time (iat, issuedAt) is not the authentication time: a refreshed token carries a new one. */
            private List<String> authTimeKeys = List.of("authenticationTime", "authenticatedAt", "loginTime", "auth_time");
            private List<String> amrKeys = List.of("amr");
            private List<String> attributeKeys = List.of(
                    "organizationId", "orgId", "tenantId", "department", "team", "email", "loginIp",
                    "authenticationType", "authenticationAssurance", "mfaVerified", "mfaCompleted", "authenticatedAt", "loginTime",
                    "iss", "aud", "azp", "scope", "scp", "amr", "acr", "challengeVerifiedAt");
        }
    }

    @Data
    public static class Authorization {
        @NestedConfigurationProperty
        private SecurityContext securityContext = new SecurityContext();

        @Data
        public static class SecurityContext {
            private boolean enabled = true;
            private List<String> authorizationEffectKeys = List.of("authorizationEffect", "effect", "decision", "decisionEffect");
            private List<String> privilegedKeys = List.of("privileged", "isPrivileged", "privilegedFlow");
            private List<String> policyIdKeys = List.of("policyId", "policy", "decisionPolicy");
            private List<String> policyVersionKeys = List.of("policyVersion", "version");
            private List<String> scopeTagKeys = List.of("scopeTags", "scopes", "scope", "permissionScopes", "scp");
            private List<String> roleKeys = List.of("effectiveRoles", "roles", "roleSet", "groups");
            private List<String> authorityKeys = List.of("effectiveAuthorities", "authorities", "permissions", "grantedAuthorities", "scope", "scp");
            private List<String> attributeKeys = List.of(
                    "authorizationEffect", "effect", "privileged", "policyId", "policyVersion",
                    "scopeTags", "scopes", "scope", "scp", "roles", "effectiveRoles", "permissions", "effectiveAuthorities");
        }
    }

    @Data
    public static class Delegation {
        @NestedConfigurationProperty
        private Token token = new Token();

        /**
         * The delegation an OAuth2 access token states (A1-1, AG-11a). An agent arrives in one of several token forms:
         * an RFC 8693 actor claim; the agent as the authorized party ({@code client_id}/{@code azp}) and the user as
         * {@code sub} (IETF WIMSE AIMS, Microsoft Entra Agent ID); snake_case delegation claims. RFC 9396
         * {@code authorization_details} carry the delegated operations and resources. A token that names no agent states
         * no delegation; an approved agent signed in with its own account, or the delegation of a {@code ContexaSubject},
         * may still state one (bridge v2).
         */
        @Data
        public static class Token {
            private boolean enabled = true;
            /** RFC 8693 actor claims; the outermost is the current actor, nested ones are prior actors. */
            private List<String> actorClaims = List.of("act");
            /** RFC 8693 claims naming who may act for the subject; kept as information only. */
            private List<String> mayActClaims = List.of("may_act");
            /** Claims naming the client the token was issued to (the agent in the AIMS and Entra forms). */
            private List<String> clientIdClaims = List.of("azp", "client_id", "appid");
            /** Claims naming the agent directly. */
            private List<String> agentIdClaims = List.of("agent_id", "agentId");
            /**
             * Claims whose values mark the token's actor as an agent, by claim name; a claim holding several values
             * separated by spaces matches when any value is listed (Entra {@code xms_act_fct} 11 = AgentIdentity).
             */
            private Map<String, List<String>> agentActorMarkers = new LinkedHashMap<>(Map.of("xms_act_fct", List.of("11")));
            /** Claims whose values state the token is a delegation to an agent, by claim name. */
            private Map<String, List<String>> delegatedMarkers = new LinkedHashMap<>(Map.of("execution_mode", List.of("DELEGATED_AGENT")));
            /** Client IDs the host registers as agents, for authorization servers that mark agents no other way. */
            private List<String> agentClientIds = List.of();
            /**
             * Claims naming the tenant a token belongs to (Entra {@code tid}); the registered agent lookup is scoped to
             * it, and a token without one is looked up as the single-tenant deployment's.
             */
            private List<String> tenantClaims = List.of("tid", "tenant_id");
            /**
             * Claims naming the delegation a token belongs to; recorded as the delegation ID and, when the token
             * carries no login session ({@code sid}), the session an agent's requests are grouped by (A1-11).
             */
            private List<String> delegationIdClaims = List.of("delegation_id", "delegationId");
            /** Claims stating whether the subject is a user or an application (Entra {@code idtyp}, Auth0 {@code sub_profile}). */
            private List<String> subjectTypeClaims = List.of("idtyp", "sub_profile");
            /** Subject type values that mean a person, so the agent acts for that person. */
            private List<String> userSubjectTypes = List.of("user");
            private List<String> scopeClaims = List.of("scope", "scp");
            /** RFC 9396 authorization details. */
            private List<String> authorizationDetailsClaims = List.of("authorization_details");
            private List<String> objectiveIdClaims = List.of("objective_id", "objectiveId");
            private List<String> objectiveFamilyClaims = List.of("objective_family", "objectiveFamily");
            private List<String> objectiveSummaryClaims = List.of("task_purpose", "objective_summary", "objectiveSummary");
            private List<String> allowedOperationsClaims = List.of("allowed_operations", "allowedOperations");
            private List<String> allowedResourcesClaims = List.of("allowed_resources", "allowed_resource_families", "allowedResources");
            private List<String> approvalRequiredClaims = List.of("approval_required", "approvalRequired");
            private List<String> privilegedExportAllowedClaims = List.of("privileged_export_allowed", "privilegedExportAllowed");
            private List<String> containmentOnlyClaims = List.of("containment_only", "containmentOnly");
            /** Claims stating when the delegation ends; without one, a delegation ends no later than the token. */
            private List<String> expiresAtClaims = List.of("delegation_expires_at", "execution_expires_at", "delegationExpiresAt");
        }
    }

    /**
     * The step-up of a CHALLENGE in mode SANDBOX, where the application signs its users in itself. Besides Contexa's verification-only
     * factors, the application's own re-authentication answers a CHALLENGE when the bridge sees a completed MFA newer
     * than the CHALLENGE and the application said where it re-authenticates; this is where the step-up page sends the
     * user for it.
     */
    @Data
    public static class StepUp {
        /**
         * Where the application re-authenticates the signed-in user with its own MFA or identity provider (for example
         * an OIDC authorization request with {@code prompt=login} or {@code max_age=0}); not offered when empty. Empty,
         * the application's own sign-in answers no CHALLENGE, whatever MFA the principal shows.
         */
        private String reauthenticationUrl;

        /**
         * Lets the step-up use the passkeys the application already keeps in repositories of its own, one of each type.
         * Off, Contexa's step-up keeps its passkeys in Contexa's tables and users register one there.
         */
        private boolean shareApplicationPasskeys = false;
    }

    @Data
    public static class Sync {
        private boolean enabled = true;
        private long minRefreshIntervalSeconds = 60;
        private String syntheticEmailDomain = "shadow.contexa.local";
    }

    @Data
    public static class Network {
        private boolean trustedProxyValidationEnabled = true;
        private List<String> trustedProxies = List.of();
    }

    /** bridge v2: how Contexa calls the application's {@code ContexaSubjectResolver}. */
    @Data
    public static class Resolver {
        /** Paths the resolver is not called for (Ant patterns on the servlet path), such as static resources. */
        private List<String> excludePaths = List.of();
        /** A call taking longer than this is reported; the call is never cut short. */
        private Duration slowThreshold = Duration.ofMillis(100);
    }
}
