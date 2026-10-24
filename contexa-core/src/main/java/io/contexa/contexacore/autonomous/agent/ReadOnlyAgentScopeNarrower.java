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
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;

import java.time.Duration;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Optional;

/**
 * The default narrowing (docs/agent A5-4): after a decision that found an agent's request risky, the agent's later
 * requests only read for a period. Risky is a decision that did not let the request through as it was (CHALLENGE,
 * ESCALATE or BLOCK), or an ALLOW whose risk reached the threshold. A BLOCK keeps the agent narrowed after its
 * release until the period ends; a person's request is never narrowed.
 */
public class ReadOnlyAgentScopeNarrower implements AgentScopeNarrower {

    private final Duration period;
    private final double riskThreshold;

    public ReadOnlyAgentScopeNarrower(Duration period, double riskThreshold) {
        this.period = period != null && !period.isNegative() && !period.isZero() ? period : Duration.ofHours(1);
        this.riskThreshold = riskThreshold;
    }

    @Override
    public Optional<Narrowing> narrowing(ZeroTrustSubject subject, SecurityEvent event, ProcessingResult result) {
        if (subject == null || subject.agentId() == null || result == null) {
            return Optional.empty();
        }
        ZeroTrustAction action = ZeroTrustAction.fromString(result.getAction());
        double risk = risk(result);
        boolean risky = action == ZeroTrustAction.CHALLENGE || action == ZeroTrustAction.ESCALATE
                || action == ZeroTrustAction.BLOCK
                || (action == ZeroTrustAction.ALLOW && risk >= riskThreshold);
        if (!risky) {
            return Optional.empty();
        }
        return Optional.of(new Narrowing(EnumSet.of(ActionFamily.READ), period,
                "A " + action.name() + " decision (risk " + String.format(Locale.ROOT, "%.2f", risk)
                        + ") narrowed the agent to reading"));
    }

    /** The decision's risk: the one it was enforced with, else the model's. */
    private static double risk(ProcessingResult result) {
        Double risk = result.getRiskScore() != null ? result.getRiskScore() : result.resolveAuditRiskScore();
        return risk != null ? risk : 0.0;
    }
}
