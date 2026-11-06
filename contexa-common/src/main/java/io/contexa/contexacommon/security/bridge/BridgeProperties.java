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

import io.contexa.contexacommon.operating.OwnershipBehaviour;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
@ConfigurationProperties(prefix = "contexa.bridge")
public class BridgeProperties {

    private boolean enabled = true;

    private SecurityOwnershipMode ownership = SecurityOwnershipMode.HOST_OWNED;

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

    public boolean isEnabled() {
        return enabled;
    }

    public OwnershipBehaviour ownershipBehaviour() {
        return OwnershipBehaviour.of(ownership);
    }

    @Data
    public static class Authentication {
        private boolean preferSecurityContext = true;

        @NestedConfigurationProperty
        private SecurityContext securityContext = new SecurityContext();

        @NestedConfigurationProperty
        private Session session = new Session();

        @NestedConfigurationProperty
        private RequestAttributes requestAttributes = new RequestAttributes();

        @NestedConfigurationProperty
        private Headers headers = new Headers();

        @Data
        public static class SecurityContext {
            private boolean enabled = true;
            private List<String> displayNameKeys = List.of("displayName", "name", "fullName", "userName", "username", "preferred_username");
            private List<String> principalTypeKeys = List.of("principalType", "userType", "actorType", "token_use");
            private List<String> authenticationTypeKeys = List.of("authenticationType", "authMethod", "loginMethod", "method", "factorType");
            private List<String> authenticationAssuranceKeys = List.of("authenticationAssurance", "authLevel", "loa", "acr");
            private List<String> mfaKeys = List.of("mfa", "mfaVerified", "mfaCompleted", "secondFactorVerified");
            // Token issue time (iat, issuedAt) is not the authentication time: a refreshed token carries a new one.
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

        @NestedConfigurationProperty
        private Session session = new Session();

        @NestedConfigurationProperty
        private RequestAttributes requestAttributes = new RequestAttributes();

        @NestedConfigurationProperty
        private Headers headers = new Headers();

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

        @Data
        public static class Session {
            private boolean enabled = true;
            private String attribute = "";
            private List<String> attributeCandidates = List.of("currentUser", "authenticatedUser", "sessionUser", "userSession", "principal", "user", "securityUser", "authenticatedPrincipal");
            private boolean autoDiscover = true;
            private String objectTypeName = "";
            private List<String> principalIdKeys = List.of("userId", "username", "id", "loginId", "email");
            private List<String> authorizationEffectKeys = List.of("authorizationEffect", "effect", "decision", "decisionEffect");
            private List<String> privilegedKeys = List.of("privileged", "isPrivileged", "privilegedFlow");
            private List<String> policyIdKeys = List.of("policyId", "policy", "decisionPolicy");
            private List<String> policyVersionKeys = List.of("policyVersion", "version");
            private List<String> scopeTagKeys = List.of("scopeTags", "scopes", "scope", "permissionScopes");
            private List<String> roleKeys = List.of("effectiveRoles", "roles", "roleSet");
            private List<String> authorityKeys = List.of("effectiveAuthorities", "authorities", "permissions", "grantedAuthorities");
            private List<String> attributeKeys = List.of(
                    "authorizationEffect", "effect", "privileged", "policyId", "policyVersion",
                    "scopeTags", "scopes", "roles", "effectiveRoles", "permissions", "effectiveAuthorities",
                    "organizationId", "orgId", "tenantId", "department", "team");
        }
    }

    @Data
    public static class Delegation {
        @NestedConfigurationProperty
        private Session session = new Session();

        @NestedConfigurationProperty
        private RequestAttributes requestAttributes = new RequestAttributes();

        @NestedConfigurationProperty
        private Headers headers = new Headers();

        @NestedConfigurationProperty
        private Token token = new Token();

        /**
         * The delegation an OAuth2 access token states (A1-1, AG-11a). An agent arrives in one of several token forms:
         * an RFC 8693 actor claim; the agent as the authorized party ({@code client_id}/{@code azp}) and the user as
         * {@code sub} (IETF WIMSE AIMS, Microsoft Entra Agent ID); snake_case delegation claims. RFC 9396
         * {@code authorization_details} carry the delegated operations and resources. A token that names no agent
         * leaves the stamp to the session, request attribute and header channels.
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

        /**
         * The delegation an application keeps in the session. Only the attribute the application names is read, and
         * the names it lists: a session also holds what the application keeps for its own pages, such as a search form
         * or a bean of a domain with agents, and a value there that names an agent would move a person's request to
         * that agent's decision, away from a restriction on the person.
         */
        @Data
        public static class Session {
            private boolean enabled = true;
            private String attribute = "";
            /** Further attribute names read for the delegation; none by default. */
            private List<String> attributeCandidates = List.of();
            /** Reads every other session attribute too; an application turns it on only if no attribute it keeps names an agent. */
            private boolean autoDiscover = false;
            private List<String> principalIdKeys = List.of("userId", "username", "id", "loginId", "email");
            private List<String> delegatedKeys = List.of("delegated", "delegationEnabled", "agentDelegated");
            private List<String> agentIdKeys = List.of("agentId", "delegateAgentId");
            private List<String> objectiveIdKeys = List.of("objectiveId", "taskPurpose", "delegationObjectiveId");
            private List<String> objectiveFamilyKeys = List.of("objectiveFamily", "objectiveType", "delegationObjectiveFamily");
            private List<String> objectiveSummaryKeys = List.of("objectiveSummary", "taskSummary", "delegationObjectiveSummary");
            private List<String> allowedOperationsKeys = List.of("allowedOperations", "delegatedOperations", "permittedOperations");
            private List<String> allowedResourcesKeys = List.of("allowedResources", "delegatedResources", "permittedResources");
            private List<String> approvalRequiredKeys = List.of("approvalRequired", "requiresApproval");
            private List<String> privilegedExportAllowedKeys = List.of("privilegedExportAllowed", "allowPrivilegedExport");
            private List<String> containmentOnlyKeys = List.of("containmentOnly", "restrictedContainment");
            private List<String> expiresAtKeys = List.of("expiresAt", "delegationExpiresAt");
            private List<String> attributeKeys = List.of(
                    "delegated", "agentId", "objectiveId", "objectiveFamily", "objectiveSummary", "allowedOperations", "allowedResources",
                    "approvalRequired", "privilegedExportAllowed", "containmentOnly", "expiresAt", "organizationId", "orgId", "tenantId", "department", "team");
        }
    }

    @Data
    public static class Session {
        private boolean enabled = true;
        private String attribute = "";
        private List<String> attributeCandidates = List.of("currentUser", "authenticatedUser", "sessionUser", "userSession", "principal", "user", "securityUser", "authenticatedPrincipal");
        private boolean autoDiscover = true;
        private String objectTypeName = "";
        private List<String> principalIdKeys = List.of("userId", "username", "id", "loginId", "email");
        private List<String> displayNameKeys = List.of("displayName", "name", "fullName", "userName", "preferred_username");
        private List<String> authoritiesKeys = List.of("roles", "authorities", "permissions", "scopes");
        private List<String> authenticationTypeKeys = List.of("authenticationType", "authMethod", "loginMethod");
        private List<String> authenticationAssuranceKeys = List.of("authenticationAssurance", "authLevel", "loa");
        private List<String> mfaKeys = List.of("mfa", "mfaVerified", "mfa_verified");
        private List<String> authTimeKeys = List.of("authenticationTime", "authenticatedAt", "loginTime");
        private List<String> attributeKeys = List.of("department", "tenantId", "organizationId", "orgId", "authMethod", "loginIp", "loginTime");
    }

    @Data
    public static class RequestAttributes {
        private boolean enabled = true;
        private String attribute = "";
        private List<String> attributeCandidates = List.of("currentUser", "authenticatedUser", "requestUser", "principal", "user", "authenticatedPrincipal", "authUser");
        private boolean autoDiscover = true;
        private String objectTypeName = "";
        private List<String> principalIdKeys = List.of("userId", "username", "id", "loginId", "email");
        private List<String> displayNameKeys = List.of("displayName", "name", "fullName", "userName", "preferred_username");
        private List<String> authoritiesKeys = List.of("roles", "authorities", "permissions", "scopes");
        private List<String> authenticationTypeKeys = List.of("authenticationType", "authMethod", "loginMethod");
        private List<String> authenticationAssuranceKeys = List.of("authenticationAssurance", "authLevel", "loa");
        private List<String> mfaKeys = List.of("mfa", "mfaVerified", "mfa_verified");
        private List<String> authTimeKeys = List.of("authenticationTime", "authenticatedAt", "loginTime");
        private List<String> attributeKeys = List.of("department", "tenantId", "organizationId", "orgId", "authMethod", "loginIp", "loginTime");

        private String flatPrincipalId = "ctxa.auth.principalId";
        private String flatDisplayName = "ctxa.auth.displayName";
        private String flatAuthenticated = "ctxa.auth.authenticated";
        private String flatAuthorities = "ctxa.auth.authorities";
        private String flatTenantId = "ctxa.auth.tenantId";
        private String flatOrganizationId = "ctxa.auth.organizationId";
        private String flatOrgId = "ctxa.auth.orgId";
        private String flatAuthenticationType = "ctxa.auth.type";
        private String flatAuthenticationAssurance = "ctxa.auth.assurance";
        private String flatMfaCompleted = "ctxa.auth.mfaCompleted";
        private String flatAuthenticationTime = "ctxa.auth.time";

        private String authorizationEffect = "ctxa.authz.effect";
        private String privileged = "ctxa.authz.privileged";
        private String policyId = "ctxa.authz.policyId";
        private String policyVersion = "ctxa.authz.policyVersion";
        private String scopeTags = "ctxa.authz.scopeTags";
        private String effectiveRoles = "ctxa.authz.roles";
        private String effectiveAuthorities = "ctxa.authz.authorities";

        private String delegated = "ctxa.delegation.enabled";
        private String agentId = "ctxa.delegation.agentId";
        private String objectiveId = "ctxa.delegation.objectiveId";
        private String objectiveFamily = "ctxa.delegation.objectiveFamily";
        private String objectiveSummary = "ctxa.delegation.objectiveSummary";
        private String allowedOperations = "ctxa.delegation.allowedOperations";
        private String allowedResources = "ctxa.delegation.allowedResources";
        private String approvalRequired = "ctxa.delegation.approvalRequired";
        private String privilegedExportAllowed = "ctxa.delegation.privilegedExportAllowed";
        private String containmentOnly = "ctxa.delegation.containmentOnly";
        private String expiresAt = "ctxa.delegation.expiresAt";
    }

    @Data
    public static class Headers {
        private boolean enabled = false;
        private String principalId = "X-Contexa-Principal-Id";
        private String displayName = "X-Contexa-Principal-Name";
        private String authenticated = "X-Contexa-Authenticated";
        private String authorities = "X-Contexa-Authorities";
        private String tenantId = "X-Contexa-Tenant-Id";
        private String organizationId = "X-Contexa-Organization-Id";
        private String orgId = "X-Contexa-Org-Id";
        private String authenticationType = "X-Contexa-Authentication-Type";
        private String authenticationAssurance = "X-Contexa-Authentication-Assurance";
        private String mfaCompleted = "X-Contexa-Mfa-Completed";
        private String authenticationTime = "X-Contexa-Authenticated-At";

        private String authorizationEffect = "X-Contexa-Authz-Effect";
        private String privileged = "X-Contexa-Authz-Privileged";
        private String policyId = "X-Contexa-Authz-Policy";
        private String policyVersion = "X-Contexa-Authz-Policy-Version";
        private String scopeTags = "X-Contexa-Authz-Scope";
        private String effectiveRoles = "X-Contexa-Authz-Roles";
        private String effectiveAuthorities = "X-Contexa-Authz-Authorities";

        private String delegated = "X-Contexa-Delegated";
        private String agentId = "X-Contexa-Agent-Id";
        private String objectiveId = "X-Contexa-Objective-Id";
        private String objectiveFamily = "X-Contexa-Objective-Family";
        private String objectiveSummary = "X-Contexa-Objective-Summary";
        private String allowedOperations = "X-Contexa-Allowed-Operations";
        private String allowedResources = "X-Contexa-Allowed-Resources";
        private String approvalRequired = "X-Contexa-Approval-Required";
        private String privilegedExportAllowed = "X-Contexa-Privileged-Export-Allowed";
        private String containmentOnly = "X-Contexa-Containment-Only";
        private String expiresAt = "X-Contexa-Delegation-Expires-At";
    }

    /**
     * The step-up of a CHALLENGE when the application owns sign-in (HOST_OWNED). Besides Contexa's verification-only
     * factors, the application's own re-authentication answers a CHALLENGE when the bridge sees a completed MFA newer
     * than the CHALLENGE; this is where the step-up page sends the user for it.
     */
    @Data
    public static class StepUp {
        /**
         * Where the application re-authenticates the signed-in user with its own MFA or identity provider (for example
         * an OIDC authorization request with {@code prompt=login} or {@code max_age=0}); not offered when empty.
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
}
