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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

/**
 * How a decision on an agent's request narrows the scope of its later requests (docs/agent A5-4). The default
 * narrows to reading for a period after a decision that found the request risky ({@link ReadOnlyAgentScopeNarrower});
 * an application declares its own bean to narrow otherwise. Whatever it answers, a scope is only ever narrowed: the
 * operations it allows are intersected with the ones in force.
 */
@FunctionalInterface
public interface AgentScopeNarrower {

    /** What a decision narrows the agent to: the operations that still pass, for how long, and why. */
    record Narrowing(Set<ActionFamily> allowed, Duration period, String reason) {
    }

    /** The narrowing the decision calls for, or empty to leave the scope as it is. */
    Optional<Narrowing> narrowing(ZeroTrustSubject subject, SecurityEvent event, ProcessingResult result);
}
