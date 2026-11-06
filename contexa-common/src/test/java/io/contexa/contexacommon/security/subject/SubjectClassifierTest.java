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
package io.contexa.contexacommon.security.subject;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** A1-3 (AG-1d): one decision of who a request acts as, used by the bridge, the publisher and the canonical context. */
class SubjectClassifierTest {

    @Test
    void q17_aConsoleSessionIsTheConsolesWhateverElseIsStated() {
        SubjectClassifier.Result result = SubjectClassifier.classify(SubjectClassifier.Facts.builder()
                .consoleSession(true).actorType("HUMAN").build());

        assertThat(result.kind()).isEqualTo(SubjectKind.CONSOLE_ADMIN);
        assertThat(result.subjectType()).isEqualTo("HUMAN_USER");
    }

    @Test
    void aPersonWithoutAgentFactsIsAHumanUser() {
        SubjectClassifier.Result result = SubjectClassifier.classify(facts().build());

        assertThat(result.kind()).isEqualTo(SubjectKind.HUMAN_USER);
        assertThat(result.subjectType()).isEqualTo("HUMAN_USER");
        assertThat(result.executionMode()).isEqualTo("DIRECT_USER");
        assertThat(result.lineageState()).isEqualTo("DIRECT");
    }

    @Test
    void anAgentActingForAPersonIsADelegatedAgent() {
        SubjectClassifier.Result result = SubjectClassifier.classify(facts().delegated(true).agentId("agent-7").build());

        assertThat(result.kind()).isEqualTo(SubjectKind.DELEGATED_AGENT);
        assertThat(result.subjectType()).isEqualTo("AGENT_RUNTIME");
        assertThat(result.executionMode()).isEqualTo("DELEGATED_AGENT");
        assertThat(result.lineageState()).isEqualTo("DECLARED");
    }

    @Test
    void anAgentActingOnItsOwnIsAnAutonomousAgent() {
        SubjectClassifier.Result result = SubjectClassifier.classify(facts().delegated(false).agentId("agent-sp-1").build());

        assertThat(result.kind()).isEqualTo(SubjectKind.AUTONOMOUS_AGENT);
        assertThat(result.subjectType()).isEqualTo("AGENT_RUNTIME");
        assertThat(result.executionMode()).isEqualTo("AUTONOMOUS_AGENT");
        assertThat(result.lineageState()).isEqualTo("DIRECT");
    }

    @Test
    void anAgentWhoseDelegationIsNotStatedIsTreatedAsActingOnItsOwn() {
        SubjectClassifier.Result result = SubjectClassifier.classify(facts().agentId("agent-sp-1").build());

        assertThat(result.kind()).isEqualTo(SubjectKind.AUTONOMOUS_AGENT);
    }

    @Test
    void aStatedDelegationWithoutAnAgentIdIsStillADelegatedAgent() {
        // A provider may state the delegation before it knows the agent; the request is not the person's own.
        SubjectClassifier.Result result = SubjectClassifier.classify(facts().delegated(true).build());

        assertThat(result.kind()).isEqualTo(SubjectKind.DELEGATED_AGENT);
    }

    @Test
    void aStatedDelegationOutranksAModeWrittenBeforeIt() {
        // The publisher writes DIRECT_USER before providers run; a delegation stated afterwards decides.
        SubjectClassifier.Result result = SubjectClassifier.classify(facts()
                .delegated(true).declaredExecutionMode("DIRECT_USER").declaredLineageState("DIRECT").build());

        assertThat(result.kind()).isEqualTo(SubjectKind.DELEGATED_AGENT);
        assertThat(result.executionMode()).isEqualTo("DELEGATED_AGENT");
        assertThat(result.lineageState()).isEqualTo("DECLARED");
    }

    @Test
    void aDeclaredModeDecidesWhenNoDelegationFlagIsStated() {
        assertThat(SubjectClassifier.classify(facts().declaredExecutionMode("DELEGATED_AGENT").build()).kind())
                .isEqualTo(SubjectKind.DELEGATED_AGENT);
        assertThat(SubjectClassifier.classify(facts().declaredExecutionMode("AUTONOMOUS_AGENT").build()).kind())
                .isEqualTo(SubjectKind.AUTONOMOUS_AGENT);
        assertThat(SubjectClassifier.classify(facts().delegationId("dlg-1").build()).kind())
                .isEqualTo(SubjectKind.DELEGATED_AGENT);
    }

    @Test
    void agentFactsOutrankADeclaredPerson() {
        // An agent's activity is never recorded as the person's, whatever a host declared.
        SubjectClassifier.Result result = SubjectClassifier.classify(facts()
                .declaredSubjectType("HUMAN_USER").delegated(true).agentId("agent-7").build());

        assertThat(result.kind()).isEqualTo(SubjectKind.DELEGATED_AGENT);
    }

    @Test
    void agentFactsOutrankAServicePrincipalType() {
        SubjectClassifier.Result result = SubjectClassifier.classify(facts()
                .principalType("OAUTH2_CLIENT").delegated(false).agentId("agent-sp-1").build());

        assertThat(result.kind()).isEqualTo(SubjectKind.AUTONOMOUS_AGENT);
    }

    @Test
    void aServiceOrWorkloadPrincipalWithoutAgentFactsIsAServiceClient() {
        assertThat(SubjectClassifier.classify(facts().principalType("SERVICE_CLIENT").build()).kind())
                .isEqualTo(SubjectKind.SERVICE_CLIENT);
        assertThat(SubjectClassifier.classify(facts().principalType("workload").build()).kind())
                .isEqualTo(SubjectKind.SERVICE_CLIENT);
        assertThat(SubjectClassifier.classify(facts().serviceClientPrincipal(true).build()).kind())
                .isEqualTo(SubjectKind.SERVICE_CLIENT);
        assertThat(SubjectClassifier.classify(facts().declaredSubjectType("SERVICE_CLIENT").build()).kind())
                .isEqualTo(SubjectKind.SERVICE_CLIENT);
    }

    @Test
    void anImputedServiceClientLineageIsNoDelegation() {
        // The runtime marks a service client's lineage as imputed; its client id in the agent field names no agent.
        SubjectClassifier.Result result = SubjectClassifier.classify(facts()
                .agentId("tenant-runtime").declaredExecutionMode("DELEGATED_AGENT")
                .declaredLineageState("IMPUTED_SERVICE_CLIENT").serviceClientPrincipal(true).build());

        assertThat(result.kind()).isEqualTo(SubjectKind.SERVICE_CLIENT);
        assertThat(result.executionMode()).isEqualTo("DELEGATED_AGENT");
        assertThat(result.lineageState()).isEqualTo("IMPUTED_SERVICE_CLIENT");
    }

    @Test
    void anActorTypeNamingAnAgentIsAnAgent() {
        assertThat(SubjectClassifier.classify(facts().actorType("DELEGATED_AGENT").build()).kind())
                .isEqualTo(SubjectKind.DELEGATED_AGENT);
        assertThat(SubjectClassifier.classify(facts().actorType("AI_AGENT").build()).kind())
                .isEqualTo(SubjectKind.AUTONOMOUS_AGENT);
    }

    @Test
    void aDeclaredLineageIsKeptWhenItAgreesWithTheKind() {
        assertThat(SubjectClassifier.classify(facts().delegated(true).declaredLineageState("VERIFIED").build())
                .lineageState()).isEqualTo("VERIFIED");
        assertThat(SubjectClassifier.classify(facts().declaredLineageState("DECLARED").build()).lineageState())
                .isEqualTo("DIRECT");
    }

    @Test
    void aKindIsFoundAgainFromTheRecordedSubjectTypeAndMode() {
        assertThat(SubjectKind.from("HUMAN_USER", "DIRECT_USER")).isEqualTo(SubjectKind.HUMAN_USER);
        assertThat(SubjectKind.from("AGENT_RUNTIME", "DELEGATED_AGENT")).isEqualTo(SubjectKind.DELEGATED_AGENT);
        assertThat(SubjectKind.from("AGENT_RUNTIME", "AUTONOMOUS_AGENT")).isEqualTo(SubjectKind.AUTONOMOUS_AGENT);
        assertThat(SubjectKind.from("SERVICE_CLIENT", "DIRECT_USER")).isEqualTo(SubjectKind.SERVICE_CLIENT);
        assertThat(SubjectKind.from(null, null)).isNull();
        assertThat(SubjectKind.AUTONOMOUS_AGENT.agent()).isTrue();
        assertThat(SubjectKind.SERVICE_CLIENT.agent()).isFalse();
    }

    private static SubjectClassifier.Facts.Builder facts() {
        return SubjectClassifier.Facts.builder();
    }
}
