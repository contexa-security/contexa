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
package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.execution.CanonicalExecutionBinding;
import io.contexa.contexacore.autonomous.execution.DelegatedExecutionContext;
import io.contexa.contexacore.autonomous.execution.ExecutionProtocolTypes;
import io.contexa.contexacore.autonomous.execution.ExecutionSubjectTypes;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** W1-13 (S-11): the publisher's UNKNOWN protocol placeholder no longer hides the protocol of the request's kind. */
class CanonicalExecutionContextResolverTest {

    private final CanonicalExecutionContextResolver resolver = new CanonicalExecutionContextResolver();

    @Test
    void aHumanRequestWithAnUnknownProtocolIsAHumanSession() {
        CanonicalSecurityContext context = context("EMPLOYEE", null, "UNKNOWN");

        assertThat(protocolOf(context)).isEqualTo(ExecutionProtocolTypes.HUMAN_SESSION);
    }

    @Test
    void aServiceClientWithAnUnknownProtocolIsAnInternalRuntime() {
        CanonicalSecurityContext context = context("SERVICE_CLIENT", null, "unknown");

        assertThat(protocolOf(context)).isEqualTo(ExecutionProtocolTypes.INTERNAL_RUNTIME);
    }

    @Test
    void aDelegatedRunWithoutADeclaredProtocolStaysUnknown() {
        CanonicalSecurityContext context = context("EMPLOYEE", CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .agentId("agent-7")
                .build(), "UNKNOWN");

        // An agent acting for the user is not the user's own session; without a declared protocol it stays unknown.
        assertThat(protocolOf(context)).isEqualTo(ExecutionProtocolTypes.UNKNOWN);
    }

    @Test
    void aDeclaredProtocolIsKept() {
        CanonicalSecurityContext context = context("EMPLOYEE", CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .agentId("agent-7")
                .build(), ExecutionProtocolTypes.MCP);

        assertThat(protocolOf(context)).isEqualTo(ExecutionProtocolTypes.MCP);
    }

    /** A1-3: a delegation a provider states after publishing outranks the DIRECT_USER the publisher wrote. */
    @Test
    void aDelegationStatedAfterPublishingOutranksThePublishersMode() {
        CanonicalSecurityContext context = context("EMPLOYEE", CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .build(), "UNKNOWN");
        context.getAttributes().put("executionSubjectType", "HUMAN_USER");
        context.getAttributes().put("executionMode", "DIRECT_USER");
        context.getAttributes().put("lineageState", "DIRECT");

        CanonicalExecutionBinding binding = resolver.resolveBinding(context);

        // Before A1-3 the publisher's DIRECT_USER won and, without an agent ID, the request stayed a person's.
        assertThat(binding.executionSubject().subjectType()).isEqualTo(ExecutionSubjectTypes.AGENT_RUNTIME);
        assertThat(binding.executionEnvelope().executionMode())
                .isEqualTo(DelegatedExecutionContext.EXECUTION_MODE_DELEGATED_AGENT);
        assertThat(binding.executionEnvelope().lineageState()).isEqualTo(DelegatedExecutionContext.LINEAGE_STATE_DECLARED);
    }

    /** A1-3: an agent acting on its own is an agent subject in the autonomous mode, not a delegated one. */
    @Test
    void anAgentActingOnItsOwnIsAnAutonomousAgent() {
        CanonicalSecurityContext context = context(null, CanonicalSecurityContext.Delegation.builder()
                .delegated(false)
                .agentId("agent-sp-1")
                .build(), "UNKNOWN");

        CanonicalExecutionBinding binding = resolver.resolveBinding(context);

        assertThat(binding.executionSubject().subjectType()).isEqualTo(ExecutionSubjectTypes.AGENT_RUNTIME);
        assertThat(binding.executionSubject().delegatedAgentProfile().agentClass())
                .isEqualTo(DelegatedExecutionContext.EXECUTION_MODE_AUTONOMOUS_AGENT);
        assertThat(binding.executionEnvelope().executionMode())
                .isEqualTo(DelegatedExecutionContext.EXECUTION_MODE_AUTONOMOUS_AGENT);
        assertThat(binding.executionEnvelope().lineageState()).isEqualTo(DelegatedExecutionContext.LINEAGE_STATE_DIRECT);
    }

    /** A1-3: a person's request keeps today's subject, mode and protocol. */
    @Test
    void aPersonsRequestStaysAHumanUser() {
        CanonicalExecutionBinding binding = resolver.resolveBinding(context("EMPLOYEE", null, "UNKNOWN"));

        assertThat(binding.executionSubject().subjectType()).isEqualTo(ExecutionSubjectTypes.HUMAN_USER);
        assertThat(binding.executionEnvelope().executionMode())
                .isEqualTo(DelegatedExecutionContext.EXECUTION_MODE_DIRECT_USER);
        assertThat(binding.executionEnvelope().provenance().protocolType()).isEqualTo(ExecutionProtocolTypes.HUMAN_SESSION);
    }

    /** A1-3: a client's own token, which the bridge stamps as SERVICE_CLIENT, is a service client. */
    @Test
    void aClientsOwnTokenIsAServiceClient() {
        CanonicalExecutionBinding binding = resolver.resolveBinding(context("SERVICE_CLIENT", null, "UNKNOWN"));

        assertThat(binding.executionSubject().subjectType()).isEqualTo(ExecutionSubjectTypes.SERVICE_CLIENT);
    }

    private CanonicalSecurityContext context(String principalType, CanonicalSecurityContext.Delegation delegation,
                                             String sourceProtocol) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sourceProtocol", sourceProtocol);
        return CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .principalType(principalType)
                        .build())
                .delegation(delegation)
                .attributes(attributes)
                .build();
    }

    private String protocolOf(CanonicalSecurityContext context) {
        return resolver.resolveBinding(context).executionEnvelope().provenance().protocolType();
    }
}
