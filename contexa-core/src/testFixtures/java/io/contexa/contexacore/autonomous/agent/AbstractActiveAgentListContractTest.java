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

package io.contexa.contexacore.autonomous.agent;

import io.contexa.contexacommon.security.bridge.runtime.RequestPathDatabaseGuard;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The approved agents the list in memory names are the ones the registry names, for every kind of registration and for
 * every change, whichever registry keeps them: a request is read from the list as the registry would answer it, and a
 * change made through the registry in this JVM shows in the list at once, without waiting for the next reading.
 */
public abstract class AbstractActiveAgentListContractTest {

    private static final Instant SEEN = Instant.parse("2026-11-11T01:00:00Z");

    private AgentRegistry registry;
    private ActiveAgentList list;
    private RequestPathDatabaseGuard guard;
    private AgentClientDirectory directory;

    /** A new, empty registry of the kind under test. */
    protected abstract AgentRegistry newRegistry();

    @BeforeEach
    void openRegistry() {
        registry = newRegistry();
        list = new ActiveAgentList(registry);
        list.start();
        guard = new RequestPathDatabaseGuard();
        directory = new RegistryAgentClientDirectory(registry, guard, list);
    }

    @AfterEach
    void closeList() {
        list.stop();
        guard.destroy();
    }

    @Test
    void anApprovedAgentIsNamedByItsClientAndByItsIdentifier() {
        register(null, "report-bot", "report-client");

        assertAgree(null, "report-client", "report-bot", "nobody");
        assertThat(directory.requestPathActiveAgentForClient(null, "report-client")).contains("report-bot");
        assertThat(directory.requestPathActiveAgentForAccount(null, "report-bot")).contains("report-bot");
        assertThat(directory.requestPathActiveAgentForAccount(null, "alice")).isEmpty();
    }

    @Test
    void anAgentThatIsNotApprovedOrNotInServiceIsNotNamed() {
        register(null, "draft-bot", "draft-client", false);
        registry.observe(new AgentSighting(null, "seen-bot", "AUTONOMOUS_AGENT", "seen-client", SEEN));
        register(null, "old-bot", "old-client");
        registry.deregister(null, "old-bot", "retired");
        register(null, "stopped-bot", "stopped-client");
        registry.suspend(null, "stopped-bot", "stopped");

        assertAgree(null, "draft-client", "draft-bot", "seen-client", "seen-bot", "old-client", "old-bot",
                "stopped-client", "stopped-bot");
        assertThat(directory.requestPathActiveAgentForClient(null, "stopped-client")).isEmpty();
        assertThat(directory.requestPathActiveAgentForClient(null, "old-client")).isEmpty();
    }

    @Test
    void aTenantsAgentIsNamedInItsTenantOnly() {
        register("tenant-a", "tenant-bot", "tenant-client");
        register(null, "solo-bot", "solo-client");

        assertAgree("tenant-a", "tenant-client", "tenant-bot");
        assertAgree(null, "tenant-client", "solo-client", "tenant-bot");
        assertAgree("tenant-b", "tenant-client", "solo-client");
        assertThat(directory.requestPathActiveAgentForClient("tenant-a", "tenant-client")).contains("tenant-bot");
        assertThat(directory.requestPathActiveAgentForClient(null, "tenant-client")).isEmpty();
        assertThat(directory.requestPathActiveAgentForClient("tenant-b", "tenant-client")).isEmpty();
    }

    /**
     * The registry names one registration for a client: the first by identifier among those whose client it is, else the
     * one whose identifier it is. A registration that is not an approved agent in service still takes the client from one
     * that is, and the list says what the registry says.
     */
    @Test
    void aRegistrationThatSharesTheClientTakesItFromTheApprovedAgentAsTheRegistryDoes() {
        register(null, "report-bot", "report-client");
        registry.observe(new AgentSighting(null, "a-bot", "AUTONOMOUS_AGENT", "report-client", SEEN));
        list.refresh();

        assertAgree(null, "report-client", "report-bot", "a-bot");
        assertThat(directory.requestPathActiveAgentForClient(null, "report-client"))
                .isEqualTo(directory.activeAgentForClient(null, "report-client"));
    }

    @Test
    void aClientThatIsAnotherAgentsIdentifierIsChosenAsTheRegistryChoosesIt() {
        register(null, "report-client", "other-client");
        register(null, "report-bot", "report-client");
        registry.observe(new AgentSighting(null, "zz-observer", "AUTONOMOUS_AGENT", "report-client", SEEN));
        list.refresh();

        assertAgree(null, "report-client", "other-client", "report-bot", "zz-observer");
    }

    /** A registration that names an approved agent's identifier as its client is chosen for that name before the approved agent is. */
    @Test
    void aRegistrationThatNamesAnApprovedAgentsIdentifierAsItsClientIsChosenBeforeIt() {
        register(null, "solo-bot", "solo-client");
        registry.observe(new AgentSighting(null, "b-bot", "AUTONOMOUS_AGENT", "solo-bot", SEEN));
        list.refresh();

        assertAgree(null, "solo-bot", "solo-client", "b-bot");
        assertThat(directory.requestPathActiveAgentForClient(null, "solo-bot"))
                .isEqualTo(directory.activeAgentForClient(null, "solo-bot"));
    }

    @Test
    void aChangeMadeThroughTheRegistryShowsAtOnce() {
        assertThat(directory.requestPathActiveAgentForClient(null, "report-client")).isEmpty();

        register(null, "report-bot", "report-client");
        assertThat(directory.requestPathActiveAgentForClient(null, "report-client")).contains("report-bot");
        assertAgree(null, "report-client", "report-bot");

        registry.suspend(null, "report-bot", "stopped");
        assertThat(directory.requestPathActiveAgentForClient(null, "report-client")).isEmpty();
        assertAgree(null, "report-client", "report-bot");

        registry.resume(null, "report-bot", "released");
        assertThat(directory.requestPathActiveAgentForClient(null, "report-client")).contains("report-bot");
        assertAgree(null, "report-client", "report-bot");

        registry.deregister(null, "report-bot", "retired");
        assertThat(directory.requestPathActiveAgentForClient(null, "report-client")).isEmpty();
        assertAgree(null, "report-client", "report-bot");

        register(null, "report-bot", "report-client");
        assertThat(directory.requestPathActiveAgentForClient(null, "report-client")).contains("report-bot");

        registry.remove(null, "report-bot");
        assertThat(directory.requestPathActiveAgentForClient(null, "report-client")).isEmpty();
        assertAgree(null, "report-client", "report-bot");
    }

    @Test
    void aClientTheRegistryChangedToAnotherAgentIsNamedAsTheNewOne() {
        register(null, "first-bot", "shared-client");
        assertThat(directory.requestPathActiveAgentForClient(null, "shared-client")).contains("first-bot");

        register(null, "a-bot", "shared-client");
        assertAgree(null, "shared-client", "first-bot", "a-bot");
        assertThat(directory.requestPathActiveAgentForClient(null, "shared-client")).contains("a-bot");

        registry.suspend(null, "a-bot", "stopped");
        assertAgree(null, "shared-client", "first-bot", "a-bot");
        assertThat(directory.requestPathActiveAgentForClient(null, "shared-client")).isEmpty();
    }

    @Test
    void whatTheRegistryReadsAgainIsWhatItHolds() {
        register(null, "report-bot", "report-client");
        register("tenant-a", "tenant-bot", "tenant-client");
        register(null, "draft-bot", "draft-client", false);
        registry.suspend("tenant-a", "tenant-bot", "stopped");
        registry.observe(new AgentSighting(null, "seen-bot", "AUTONOMOUS_AGENT", "report-client", SEEN));

        list.refresh();

        assertAgree(null, "report-client", "report-bot", "draft-client", "draft-bot", "seen-bot");
        assertAgree("tenant-a", "tenant-client", "tenant-bot");
    }

    @Test
    void theApprovalsAreTheApprovedAndWhateverCouldBeChosenForTheirClients() {
        register(null, "report-bot", "report-client");
        register("tenant-a", "tenant-bot", "tenant-client");
        registry.suspend("tenant-a", "tenant-bot", "stopped");
        register(null, "draft-bot", "draft-client", false);
        registry.observe(new AgentSighting(null, "seen-bot", "AUTONOMOUS_AGENT", "seen-client", SEEN));
        registry.observe(new AgentSighting(null, "shadow-bot", "AUTONOMOUS_AGENT", "report-client", SEEN));
        registry.observe(new AgentSighting("tenant-b", "elsewhere-bot", "AUTONOMOUS_AGENT", "report-client", SEEN));

        List<AgentApproval> approvals = registry.approvals(10);

        assertThat(approvals).containsExactlyInAnyOrder(
                new AgentApproval(null, "report-bot", "report-client", AgentStatus.ACTIVE, true),
                new AgentApproval("tenant-a", "tenant-bot", "tenant-client", AgentStatus.SUSPENDED, true),
                new AgentApproval(null, "shadow-bot", "report-client", AgentStatus.ACTIVE, false));
    }

    @Test
    void moreApprovalsThanTheLimitIsAFailureAndNeverAListThatLeavesAgentsOut() {
        register(null, "bot-1", "client-1");
        register(null, "bot-2", "client-2");
        register(null, "bot-3", "client-3");

        assertThat(registry.approvals(3)).hasSize(3);
        assertThatThrownBy(() -> registry.approvals(2)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> registry.approvals(0)).isInstanceOf(IllegalStateException.class);
    }

    private void assertAgree(String tenantId, String... names) {
        for (String name : names) {
            Optional<String> inMemory = directory.requestPathActiveAgentForClient(tenantId, name);
            Optional<String> registryAnswer = directory.activeAgentForClient(tenantId, name);
            assertThat(inMemory).as("tenant %s, name %s", tenantId, name).isEqualTo(registryAnswer);
        }
    }

    private void register(String tenantId, String agentId, String clientId) {
        register(tenantId, agentId, clientId, true);
    }

    private void register(String tenantId, String agentId, String clientId, boolean allowlisted) {
        registry.register(new AgentRegistrationRequest(tenantId, agentId, agentId, "AGENT", clientId, "sponsor",
                allowlisted));
    }
}
