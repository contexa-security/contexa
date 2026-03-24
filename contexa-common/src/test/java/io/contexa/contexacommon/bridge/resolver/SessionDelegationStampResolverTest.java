package io.contexa.contexacommon.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.resolver.SessionDelegationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SessionDelegationStampResolverTest {

    private final SessionDelegationStampResolver resolver = new SessionDelegationStampResolver();

    @Test
    void shouldExtractDelegationContextFromSessionObject() {
        SessionDelegation sessionDelegation = new SessionDelegation();
        sessionDelegation.setUserId("alice");
        sessionDelegation.setDelegated(true);
        sessionDelegation.setAgentId("agent-1");
        sessionDelegation.setObjectiveId("objective-1");
        sessionDelegation.setObjectiveSummary("Export monthly report");
        sessionDelegation.setAllowedOperations(List.of("EXPORT"));
        sessionDelegation.setAllowedResources(List.of("report:monthly"));
        sessionDelegation.setApprovalRequired(true);
        sessionDelegation.setContainmentOnly(false);
        sessionDelegation.setExpiresAt(Instant.parse("2026-03-24T00:00:00Z"));

        MockHttpSession session = new MockHttpSession();
        session.setAttribute("LOGIN_USER", sessionDelegation);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/reports/export");
        request.setSession(session);

        DelegationStamp stamp = resolver.resolve(
                request,
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                new BridgeProperties()
        ).orElseThrow();

        assertThat(stamp.subjectId()).isEqualTo("alice");
        assertThat(stamp.delegated()).isTrue();
        assertThat(stamp.agentId()).isEqualTo("agent-1");
        assertThat(stamp.objectiveId()).isEqualTo("objective-1");
        assertThat(stamp.objectiveSummary()).isEqualTo("Export monthly report");
        assertThat(stamp.allowedOperations()).contains("EXPORT");
        assertThat(stamp.allowedResources()).contains("report:monthly");
        assertThat(stamp.approvalRequired()).isTrue();
        assertThat(stamp.containmentOnly()).isFalse();
        assertThat(stamp.expiresAt()).isEqualTo(Instant.parse("2026-03-24T00:00:00Z"));
        assertThat(stamp.attributes()).containsEntry("delegationResolver", "SESSION");
    }

    public static class SessionDelegation {
        private String userId;
        private boolean delegated;
        private String agentId;
        private String objectiveId;
        private String objectiveSummary;
        private List<String> allowedOperations = List.of();
        private List<String> allowedResources = List.of();
        private boolean approvalRequired;
        private boolean containmentOnly;
        private Instant expiresAt;

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public boolean isDelegated() {
            return delegated;
        }

        public void setDelegated(boolean delegated) {
            this.delegated = delegated;
        }

        public String getAgentId() {
            return agentId;
        }

        public void setAgentId(String agentId) {
            this.agentId = agentId;
        }

        public String getObjectiveId() {
            return objectiveId;
        }

        public void setObjectiveId(String objectiveId) {
            this.objectiveId = objectiveId;
        }

        public String getObjectiveSummary() {
            return objectiveSummary;
        }

        public void setObjectiveSummary(String objectiveSummary) {
            this.objectiveSummary = objectiveSummary;
        }

        public List<String> getAllowedOperations() {
            return allowedOperations;
        }

        public void setAllowedOperations(List<String> allowedOperations) {
            this.allowedOperations = allowedOperations;
        }

        public List<String> getAllowedResources() {
            return allowedResources;
        }

        public void setAllowedResources(List<String> allowedResources) {
            this.allowedResources = allowedResources;
        }

        public boolean isApprovalRequired() {
            return approvalRequired;
        }

        public void setApprovalRequired(boolean approvalRequired) {
            this.approvalRequired = approvalRequired;
        }

        public boolean isContainmentOnly() {
            return containmentOnly;
        }

        public void setContainmentOnly(boolean containmentOnly) {
            this.containmentOnly = containmentOnly;
        }

        public Instant getExpiresAt() {
            return expiresAt;
        }

        public void setExpiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
        }
    }
}
