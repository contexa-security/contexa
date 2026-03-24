package io.contexa.contexacore.autonomous.context;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CanonicalSecurityContext {

    private Actor actor;

    private Session session;

    private Resource resource;

    private Authorization authorization;

    private Delegation delegation;

    private Bridge bridge;

    private ObservedScope observedScope;

    private ContextCoverageReport coverage;

    @Builder.Default
    private Map<String, Object> attributes = new LinkedHashMap<>();

    @Builder.Default
    private Instant collectedAt = Instant.now();

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Actor {
        private String userId;
        private String organizationId;
        private String department;
        private String principalType;
        @Builder.Default
        private List<String> roleSet = new ArrayList<>();
        @Builder.Default
        private List<String> authoritySet = new ArrayList<>();
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Session {
        private String sessionId;
        private String clientIp;
        private String userAgent;
        private Boolean mfaVerified;
        private Integer failedLoginAttempts;
        private Integer recentRequestCount;
        private Boolean newSession;
        private Boolean newUser;
        private Boolean newDevice;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Resource {
        private String resourceId;
        private String resourceType;
        private String businessLabel;
        private String sensitivity;
        private String requestPath;
        private String httpMethod;
        private String actionFamily;
        private Boolean sensitiveResource;
        private Boolean privileged;
        private Boolean exportSensitive;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Authorization {
        @Builder.Default
        private List<String> effectiveRoles = new ArrayList<>();
        @Builder.Default
        private List<String> effectivePermissions = new ArrayList<>();
        @Builder.Default
        private List<String> scopeTags = new ArrayList<>();
        private Boolean privileged;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Delegation {
        private String agentId;
        private String objectiveId;
        private String objectiveFamily;
        @Builder.Default
        private List<String> allowedOperations = new ArrayList<>();
        @Builder.Default
        private List<String> allowedResources = new ArrayList<>();
        private Boolean privilegedExportAllowed;
        private Boolean containmentOnly;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Bridge {
        private String coverageLevel;
        private Integer coverageScore;
        @Builder.Default
        private List<String> missingContexts = new ArrayList<>();
        private String summary;
        @Builder.Default
        private List<String> remediationHints = new ArrayList<>();
        private String authenticationSource;
        private String authorizationSource;
        private String delegationSource;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ObservedScope {
        private String profileSource;
        private String summary;
        private Integer recentProtectableAccessCount;
        private Integer recentDeniedAccessCount;
        private Integer recentSensitiveAccessCount;
        @Builder.Default
        private List<String> frequentResources = new ArrayList<>();
        @Builder.Default
        private List<String> frequentActionFamilies = new ArrayList<>();
        private Boolean rareCurrentResource;
        private Boolean rareCurrentActionFamily;
    }
}
