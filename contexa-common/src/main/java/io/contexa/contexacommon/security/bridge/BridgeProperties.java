package io.contexa.contexacommon.security.bridge;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.List;

@Data
@ConfigurationProperties(prefix = "contexa.bridge")
public class BridgeProperties {

    private boolean enabled = true;

    private boolean populateSecurityContext = true;

    @NestedConfigurationProperty
    private Authentication authentication = new Authentication();

    @NestedConfigurationProperty
    private Authorization authorization = new Authorization();

    @NestedConfigurationProperty
    private Delegation delegation = new Delegation();

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
            private List<String> displayNameKeys = List.of("displayName", "name", "fullName", "userName", "username");
            private List<String> principalTypeKeys = List.of("principalType", "userType", "actorType");
            private List<String> authenticationTypeKeys = List.of("authenticationType", "authMethod", "loginMethod", "method", "factorType");
            private List<String> authenticationAssuranceKeys = List.of("authenticationAssurance", "authLevel", "loa", "acr");
            private List<String> mfaKeys = List.of("mfa", "mfaVerified", "mfaCompleted", "secondFactorVerified");
            private List<String> authTimeKeys = List.of("authenticationTime", "authenticatedAt", "loginTime", "issuedAt");
            private List<String> attributeKeys = List.of(
                    "organizationId", "orgId", "tenantId", "department", "team", "email", "loginIp",
                    "authenticationType", "authenticationAssurance", "mfaVerified", "mfaCompleted", "authenticatedAt", "loginTime");
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
            private List<String> scopeTagKeys = List.of("scopeTags", "scopes", "scope", "permissionScopes");
            private List<String> roleKeys = List.of("effectiveRoles", "roles", "roleSet");
            private List<String> authorityKeys = List.of("effectiveAuthorities", "authorities", "permissions", "grantedAuthorities");
            private List<String> attributeKeys = List.of(
                    "authorizationEffect", "effect", "privileged", "policyId", "policyVersion",
                    "scopeTags", "scopes", "roles", "effectiveRoles", "permissions", "effectiveAuthorities");
        }

        @Data
        public static class Session {
            private boolean enabled = true;
            private String attribute = "";
            private List<String> attributeCandidates = List.of("currentUser", "authenticatedUser", "sessionUser", "userSession", "principal", "user", "securityUser", "authenticatedPrincipal");
            private boolean autoDiscover = true;
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

        @Data
        public static class Session {
            private boolean enabled = true;
            private String attribute = "";
            private List<String> attributeCandidates = List.of("currentUser", "authenticatedUser", "sessionUser", "userSession", "principal", "user", "securityUser", "authenticatedPrincipal");
            private boolean autoDiscover = true;
            private List<String> principalIdKeys = List.of("userId", "username", "id", "loginId", "email");
            private List<String> delegatedKeys = List.of("delegated", "delegationEnabled", "agentDelegated");
            private List<String> agentIdKeys = List.of("agentId", "delegateAgentId");
            private List<String> objectiveIdKeys = List.of("objectiveId", "taskPurpose", "delegationObjectiveId");
            private List<String> objectiveSummaryKeys = List.of("objectiveSummary", "taskSummary", "delegationObjectiveSummary");
            private List<String> allowedOperationsKeys = List.of("allowedOperations", "delegatedOperations", "permittedOperations");
            private List<String> allowedResourcesKeys = List.of("allowedResources", "delegatedResources", "permittedResources");
            private List<String> approvalRequiredKeys = List.of("approvalRequired", "requiresApproval");
            private List<String> containmentOnlyKeys = List.of("containmentOnly", "restrictedContainment");
            private List<String> expiresAtKeys = List.of("expiresAt", "delegationExpiresAt");
            private List<String> attributeKeys = List.of(
                    "delegated", "agentId", "objectiveId", "objectiveSummary", "allowedOperations", "allowedResources",
                    "approvalRequired", "containmentOnly", "expiresAt", "organizationId", "orgId", "tenantId", "department", "team");
        }
    }

    @Data
    public static class Session {
        private boolean enabled = true;
        private String attribute = "";
        private List<String> attributeCandidates = List.of("currentUser", "authenticatedUser", "sessionUser", "userSession", "principal", "user", "securityUser", "authenticatedPrincipal");
        private boolean autoDiscover = true;
        private List<String> principalIdKeys = List.of("userId", "username", "id", "loginId", "email");
        private List<String> displayNameKeys = List.of("displayName", "name", "fullName", "userName");
        private List<String> authoritiesKeys = List.of("roles", "authorities", "permissions", "scopes");
        private List<String> authenticationTypeKeys = List.of("authenticationType", "authMethod", "loginMethod");
        private List<String> authenticationAssuranceKeys = List.of("authenticationAssurance", "authLevel", "loa");
        private List<String> mfaKeys = List.of("mfa", "mfaVerified", "mfa_verified");
        private List<String> authTimeKeys = List.of("authenticationTime", "authenticatedAt", "loginTime");
        private List<String> attributeKeys = List.of("department", "organizationId", "orgId", "authMethod", "loginIp", "loginTime");
    }

    @Data
    public static class RequestAttributes {
        private boolean enabled = true;
        private String principalId = "ctxa.auth.principalId";
        private String displayName = "ctxa.auth.displayName";
        private String authenticated = "ctxa.auth.authenticated";
        private String authorities = "ctxa.auth.authorities";
        private String authenticationType = "ctxa.auth.type";
        private String authenticationAssurance = "ctxa.auth.assurance";
        private String mfaCompleted = "ctxa.auth.mfaCompleted";
        private String authenticationTime = "ctxa.auth.time";

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
        private String objectiveSummary = "ctxa.delegation.objectiveSummary";
        private String allowedOperations = "ctxa.delegation.allowedOperations";
        private String allowedResources = "ctxa.delegation.allowedResources";
        private String approvalRequired = "ctxa.delegation.approvalRequired";
        private String containmentOnly = "ctxa.delegation.containmentOnly";
        private String expiresAt = "ctxa.delegation.expiresAt";
    }

    @Data
    public static class Headers {
        private boolean enabled = true;
        private String principalId = "X-Contexa-Principal-Id";
        private String displayName = "X-Contexa-Principal-Name";
        private String authenticated = "X-Contexa-Authenticated";
        private String authorities = "X-Contexa-Authorities";
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
        private String objectiveSummary = "X-Contexa-Objective-Summary";
        private String allowedOperations = "X-Contexa-Allowed-Operations";
        private String allowedResources = "X-Contexa-Allowed-Resources";
        private String approvalRequired = "X-Contexa-Approval-Required";
        private String containmentOnly = "X-Contexa-Containment-Only";
        private String expiresAt = "X-Contexa-Delegation-Expires-At";
    }
}
