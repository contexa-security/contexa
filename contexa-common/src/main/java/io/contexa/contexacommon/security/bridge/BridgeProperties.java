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
        private Session session = new Session();

        @NestedConfigurationProperty
        private RequestAttributes requestAttributes = new RequestAttributes();

        @NestedConfigurationProperty
        private Headers headers = new Headers();
    }

    @Data
    public static class Authorization {
        @NestedConfigurationProperty
        private RequestAttributes requestAttributes = new RequestAttributes();

        @NestedConfigurationProperty
        private Headers headers = new Headers();
    }

    @Data
    public static class Delegation {
        @NestedConfigurationProperty
        private RequestAttributes requestAttributes = new RequestAttributes();

        @NestedConfigurationProperty
        private Headers headers = new Headers();
    }

    @Data
    public static class Session {
        private boolean enabled = true;
        private String attribute = "LOGIN_USER";
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
    }
}
