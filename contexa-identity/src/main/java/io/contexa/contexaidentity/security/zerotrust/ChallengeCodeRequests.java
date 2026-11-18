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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import lombok.extern.slf4j.Slf4j;

import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Console design 6.2: the "code requested" step of a challenge's funnel (required, then a code requested, then
 * passed). A code mailed to a user whose decision in force is a CHALLENGE answers that challenge, so it is kept as an
 * outcome of the challenged request; a code mailed to anyone else (a sign-in, a user not challenged) is no such step.
 * A resent code adds another outcome; the console counts a decision once.
 */
@Slf4j
public class ChallengeCodeRequests implements Consumer<String> {

    private final Supplier<ZeroTrustActionRepository> actionRepository;
    private final Supplier<ZeroTrustDecisionOutcomes> decisionOutcomes;

    public ChallengeCodeRequests(Supplier<ZeroTrustActionRepository> actionRepository,
                                 Supplier<ZeroTrustDecisionOutcomes> decisionOutcomes) {
        this.actionRepository = actionRepository != null ? actionRepository : () -> null;
        this.decisionOutcomes = decisionOutcomes != null ? decisionOutcomes : () -> null;
    }

    /** The code mailed to the user, kept for the challenge in force when there is one. */
    @Override
    public void accept(String userId) {
        ZeroTrustActionRepository actions = actionRepository.get();
        ZeroTrustDecisionOutcomes outcomes = decisionOutcomes.get();
        if (userId == null || userId.isBlank() || actions == null || outcomes == null) {
            return;
        }
        String user = userId.trim();
        try {
            if (actions.getActionFromHash(user) != ZeroTrustAction.CHALLENGE) {
                return;
            }
            ZeroTrustActionRepository.ZeroTrustAnalysisData analysis = actions.getAnalysisData(user);
            String requestId = analysis != null ? analysis.requestId() : null;
            if (requestId == null || requestId.isBlank()) {
                return;
            }
            outcomes.record(requestId, user, null, ZeroTrustDecisionOutcomes.Kind.CHALLENGE_CODE_REQUESTED, user, null);
        } catch (RuntimeException failure) {
            log.error("[ChallengeCodeRequests] Failed to record the code requested for the challenge of user {}", user,
                    failure);
        }
    }
}
