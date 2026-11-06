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

import io.contexa.contexacore.testsupport.AgentConfirmationFirstRequestsContract;
import org.junit.jupiter.api.Test;

import java.time.Instant;

/**
 * The first requests of one agent that arrive together mail the person once with the in-memory store: the others are
 * told on the console. The database store runs the same contract in the console module.
 */
class AgentConfirmationFirstRequestsTest {

    @Test
    void twoFirstRequestsOfOneAgentMailThePersonOnce() throws Exception {
        AgentConfirmationFirstRequestsContract.twoFirstRequestsMailThePersonOnce(new InMemoryAgentConfirmationStore());
    }

    /** However long the read of the waiting confirmations takes, the second request cannot have looked before the first saved. */
    @Test
    void aSlowReadStillLetsOnlyOneRequestFindTheAgentAlone() throws Exception {
        AgentConfirmationStore slowToRead = new InMemoryAgentConfirmationStore() {
            @Override
            public boolean waiting(String subjectKey, Instant now) {
                boolean waiting = super.waiting(subjectKey, now);
                try {
                    Thread.sleep(150);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return waiting;
            }
        };

        AgentConfirmationFirstRequestsContract.twoFirstRequestsMailThePersonOnce(slowToRead);
    }

    @Test
    void aStoreThatCannotTellStillKeepsTheRequestAndMailsThePerson() throws Exception {
        AgentConfirmationStore failing = new InMemoryAgentConfirmationStore() {
            @Override
            public synchronized boolean saveNotingWaiting(AgentConfirmation confirmation, Instant now) {
                throw new IllegalStateException("the store cannot be read");
            }
        };

        AgentConfirmationFirstRequestsContract.aRequestIsKeptAndMailedWhenTheStoreCannotTell(failing);
    }

    @Test
    void manyAgentsMailThePersonOncePerAgent() throws Exception {
        AgentConfirmationFirstRequestsContract.manyAgentsMailThePersonOncePerAgent(new InMemoryAgentConfirmationStore(),
                25, 4);
    }
}
