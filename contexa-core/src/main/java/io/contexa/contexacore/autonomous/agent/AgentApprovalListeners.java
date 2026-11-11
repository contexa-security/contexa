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

import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * The listeners of one agent registry for the changes made to the approval of an agent in this JVM (see
 * {@link AgentRegistry#onApprovalChange}). A listener that fails never fails the change that was made.
 */
@Slf4j
public final class AgentApprovalListeners {

    private final List<Consumer<AgentApproval>> listeners = new CopyOnWriteArrayList<>();

    public void add(Consumer<AgentApproval> listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    /** Tells every listener, on the calling thread, what the agent's approval is now. */
    public void changed(AgentApproval now) {
        for (Consumer<AgentApproval> listener : listeners) {
            try {
                listener.accept(now);
            } catch (RuntimeException failed) {
                log.error("A listener of the agent registry failed for the agent {}", now.agentId(), failed);
            }
        }
    }
}
