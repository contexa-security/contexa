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

import io.contexa.contexacore.autonomous.execution.ExecutionProtocolTypes;
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
