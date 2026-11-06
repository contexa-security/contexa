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
package io.contexa.contexacommon.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.resolver.SessionDelegationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
        sessionDelegation.setObjectiveFamily("REPORT_EXPORT");
        sessionDelegation.setObjectiveSummary("Export monthly report");
        sessionDelegation.setAllowedOperations(List.of("EXPORT"));
        sessionDelegation.setAllowedResources(List.of("report:monthly"));
        sessionDelegation.setApprovalRequired(true);
        sessionDelegation.setPrivilegedExportAllowed(false);
        sessionDelegation.setContainmentOnly(false);
        sessionDelegation.setExpiresAt(Instant.parse("2026-03-24T00:00:00Z"));

        MockHttpSession session = new MockHttpSession();
        session.setAttribute("LOGIN_USER", sessionDelegation);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/reports/export");
        request.setSession(session);
        BridgeProperties properties = new BridgeProperties();
        properties.getDelegation().getSession().setAttribute("LOGIN_USER");

        DelegationStamp stamp = resolver.resolve(
                request,
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                properties
        ).orElseThrow();

        assertThat(stamp.subjectId()).isEqualTo("alice");
        assertThat(stamp.delegated()).isTrue();
        assertThat(stamp.agentId()).isEqualTo("agent-1");
        assertThat(stamp.objectiveId()).isEqualTo("objective-1");
        assertThat(stamp.objectiveFamily()).isEqualTo("REPORT_EXPORT");
        assertThat(stamp.objectiveSummary()).isEqualTo("Export monthly report");
        assertThat(stamp.allowedOperations()).contains("EXPORT");
        assertThat(stamp.allowedResources()).contains("report:monthly");
        assertThat(stamp.approvalRequired()).isTrue();
        assertThat(stamp.privilegedExportAllowed()).isFalse();
        assertThat(stamp.containmentOnly()).isFalse();
        assertThat(stamp.expiresAt()).isEqualTo(Instant.parse("2026-03-24T00:00:00Z"));
        assertThat(stamp.attributes()).containsEntry("delegationResolver", "SESSION");
    }

    private Optional<DelegationStamp> resolve(MockHttpSession session, BridgeProperties properties) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setSession(session);
        return resolver.resolve(request,
                new RequestContextSnapshot("/orders", "GET", "10.0.0.10", "JUnit", "session-1", "request-1", "/orders", null, false, Instant.now()),
                properties);
    }

    private static SessionDelegation delegationOf(String agentId) {
        SessionDelegation delegation = new SessionDelegation();
        delegation.setUserId("alice");
        delegation.setDelegated(true);
        delegation.setAgentId(agentId);
        return delegation;
    }

    @Test
    void whatAnApplicationKeepsInTheSessionForItsPagesIsNoDelegation() {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("lastSearch", new HashMap<>(Map.of("q", "laptop", "agentId", "x", "delegated", "true")));
        session.setAttribute("policyForm", new HashMap<>(Map.of("agentId", "sales-agent-7")));
        session.setAttribute("user", delegationOf("agent-1"));

        assertThat(resolve(session, new BridgeProperties())).isEmpty();
    }

    @Test
    void onlyTheAttributeTheApplicationNamesIsRead() {
        BridgeProperties properties = new BridgeProperties();
        properties.getDelegation().getSession().setAttribute("agentDelegation");
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("agentDelegation", delegationOf("agent-1"));
        session.setAttribute("lastSearch", new HashMap<>(Map.of("agentId", "x", "delegated", "true",
                "objectiveId", "o-1", "allowedOperations", List.of("EXPORT"))));

        DelegationStamp stamp = resolve(session, properties).orElseThrow();

        assertThat(stamp.agentId()).isEqualTo("agent-1");
        assertThat(stamp.attributes()).containsEntry("bridgeSessionAttribute", "agentDelegation");
    }

    @Test
    void anApplicationThatTurnsAutoDiscoveryOnHasEveryAttributeRead() {
        BridgeProperties properties = new BridgeProperties();
        properties.getDelegation().getSession().setAutoDiscover(true);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("LOGIN_USER", delegationOf("agent-1"));

        DelegationStamp stamp = resolve(session, properties).orElseThrow();

        assertThat(stamp.agentId()).isEqualTo("agent-1");
        assertThat(stamp.attributes()).containsEntry("bridgeSessionAttribute", "LOGIN_USER");
    }

    @Test
    void theNamesTheApplicationListsAreRead() {
        BridgeProperties properties = new BridgeProperties();
        properties.getDelegation().getSession().setAttributeCandidates(List.of("agentContext"));
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("agentContext", delegationOf("agent-1"));
        session.setAttribute("lastSearch", new HashMap<>(Map.of("agentId", "x", "delegated", "true")));

        assertThat(resolve(session, properties).orElseThrow().agentId()).isEqualTo("agent-1");
    }

    public static class SessionDelegation {
        private String userId;
        private boolean delegated;
        private String agentId;
        private String objectiveId;
        private String objectiveFamily;
        private String objectiveSummary;
        private List<String> allowedOperations = List.of();
        private List<String> allowedResources = List.of();
        private boolean approvalRequired;
        private boolean privilegedExportAllowed;
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

        public String getObjectiveFamily() {
            return objectiveFamily;
        }

        public void setObjectiveFamily(String objectiveFamily) {
            this.objectiveFamily = objectiveFamily;
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

        public boolean isPrivilegedExportAllowed() {
            return privilegedExportAllowed;
        }

        public void setPrivilegedExportAllowed(boolean privilegedExportAllowed) {
            this.privilegedExportAllowed = privilegedExportAllowed;
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
