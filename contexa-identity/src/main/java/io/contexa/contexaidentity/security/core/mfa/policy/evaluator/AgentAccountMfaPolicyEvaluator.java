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
package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * The sign-in policy of an approved agent's own account (A1-13, AG-12e). An agent cannot answer the factors made for
 * people (a code sent to a mailbox, a passkey), so its sign-in never enters the MFA flow; Contexa's zero trust action
 * for the account decides alone:
 * <ul>
 *     <li>ALLOW, or no analysis yet: signed in without factors; each request is then decided at runtime (A1-5).</li>
 *     <li>BLOCK: refused. ESCALATE: refused for review.</li>
 *     <li>CHALLENGE: refused until the agent's accountable party confirms it (A5-2), never answered with factors.</li>
 * </ul>
 * A person's account is not supported here, so people keep their policy. When the action cannot be read the sign-in is
 * refused.
 */
@Slf4j
public class AgentAccountMfaPolicyEvaluator implements MfaPolicyEvaluator {

    public static final String NAME = "AgentAccountMfaPolicyEvaluator";
    /** Metadata marking a decision made for an agent's account, which no later adaptation turns into factors. */
    public static final String SUBJECT_METADATA = "mfaSubject";
    public static final String AGENT_ACCOUNT = "AGENT_ACCOUNT";
    public static final String CONFIRMATION_REQUIRED_REASON =
            "AGENT_CONFIRMATION_REQUIRED: the agent's accountable party must confirm this sign-in";

    private final ZeroTrustActionRepository actionRepository;
    private final ObjectProvider<AgentClientDirectory> agentClientDirectory;

    public AgentAccountMfaPolicyEvaluator(ZeroTrustActionRepository actionRepository,
                                          ObjectProvider<AgentClientDirectory> agentClientDirectory) {
        this.actionRepository = actionRepository;
        this.agentClientDirectory = agentClientDirectory;
    }

    /** Whether the decision was made for an agent's account. */
    public static boolean isAgentAccountDecision(MfaDecision decision) {
        return decision != null && decision.getMetadata() != null
                && AGENT_ACCOUNT.equals(decision.getMetadata().get(SUBJECT_METADATA));
    }

    @Override
    public boolean supports(FactorContext context) {
        return context != null && agentOf(context.getUsername()).isPresent();
    }

    @Override
    public MfaDecision evaluatePolicy(FactorContext context) {
        String account = context.getUsername();
        String agentId = agentOf(account).orElse(account);
        ZeroTrustAction action;
        try {
            ZeroTrustActionRepository.ZeroTrustAnalysisData analysis = actionRepository.getAnalysisData(account);
            action = ZeroTrustAction.fromString(analysis != null ? analysis.action() : null);
        } catch (RuntimeException readFailed) {
            log.error("The zero trust action of agent account {} could not be read; its sign-in is refused", account,
                    readFailed);
            return decision(MfaDecision.blocked("Zero trust action unavailable for the agent account"), agentId, null);
        }
        return switch (action) {
            case ALLOW, PENDING_ANALYSIS -> decision(MfaDecision.noMfaRequired(), agentId, action);
            case BLOCK -> decision(MfaDecision.blocked("Zero Trust BLOCK action - agent sign-in denied"), agentId, action);
            case ESCALATE -> decision(MfaDecision.escalated("Zero Trust ESCALATE action - agent sign-in held for review"),
                    agentId, action);
            case CHALLENGE -> decision(MfaDecision.blocked(CONFIRMATION_REQUIRED_REASON), agentId, action);
        };
    }

    private static MfaDecision decision(MfaDecision base, String agentId, ZeroTrustAction action) {
        Map<String, Object> metadata = new HashMap<>();
        if (base.getMetadata() != null) {
            metadata.putAll(base.getMetadata());
        }
        metadata.put(SUBJECT_METADATA, AGENT_ACCOUNT);
        metadata.put("agentId", agentId);
        if (action != null) {
            metadata.put("zeroTrustAction", action.name());
        }
        return base.toBuilder().metadata(metadata).build();
    }

    private Optional<String> agentOf(String account) {
        if (!StringUtils.hasText(account) || agentClientDirectory == null) {
            return Optional.empty();
        }
        AgentClientDirectory directory = agentClientDirectory.getIfAvailable();
        if (directory == null) {
            return Optional.empty();
        }
        try {
            return directory.activeAgentForAccount(null, account.trim());
        } catch (RuntimeException lookupFailed) {
            log.error("The agent registry could not be asked whether account {} is an agent; the person's policy applies",
                    account, lookupFailed);
            return Optional.empty();
        }
    }

    @Override
    public int getPriority() {
        // Above every policy for people, so an agent's account never reaches a policy that asks for factors.
        return 1000;
    }

    @Override
    public String getName() {
        return NAME;
    }
}
