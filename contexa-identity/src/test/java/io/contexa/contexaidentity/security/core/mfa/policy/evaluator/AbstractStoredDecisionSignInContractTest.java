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

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-99: what a password step does with the decision stored for the user. A stored decision was reached for another
 * request, so an ALLOW in it says nothing of who is signing in now: a stolen password met no second step while the
 * victim's ALLOW lasted. Each case runs on the policy as the application wires it and on both stores, which must agree.
 */
abstract class AbstractStoredDecisionSignInContractTest {

    private static final String VICTIM_CONTEXT = "context-of-the-victims-session";
    private static final String VICTIM_ADDRESS = "203.0.113.10";
    private static final String VICTIM_BROWSER = "Mozilla/5.0 (victim)";
    private static final String THIEF_ADDRESS = "198.51.100.77";
    private static final String THIEF_BROWSER = "curl/8.5.0 (thief)";
    private static final int SIGN_INS_AT_ONCE = 16;

    private String user;
    private SignInPolicyFixture policy;

    /** The store under test. */
    protected abstract ZeroTrustActionRepository store();

    /** Ends the user's analysis as its time would; the 24-hour last verified record stays behind. */
    protected abstract void analysisRunsOut(String user);

    @BeforeEach
    void newUser() {
        // a policy without a store reads as "no decision" and asks for the second step: it would pass every case here
        assertThat(store()).as("the store under test").isNotNull();
        user = "sign-in-" + UUID.randomUUID();
        policy = new SignInPolicyFixture(store());
    }

    static Stream<Arguments> attempts() {
        return Stream.of(
                Arguments.of("another address", THIEF_ADDRESS, VICTIM_BROWSER),
                Arguments.of("another browser", VICTIM_ADDRESS, THIEF_BROWSER),
                Arguments.of("another address and browser", THIEF_ADDRESS, THIEF_BROWSER),
                Arguments.of("the same address and browser", VICTIM_ADDRESS, VICTIM_BROWSER));
    }

    @ParameterizedTest(name = "from {0}")
    @MethodSource("attempts")
    @DisplayName("the victim's stored ALLOW waives no second step of a new sign-in")
    void aStoredAllowWaivesNoSecondStep(String attempt, String address, String browser) {
        allowedInTheVictimsSession();

        MfaDecision decision = policy.provider.evaluateInitialMfaRequirement(
                SignInPolicyFixture.signIn(user, address, browser));

        assertAsksForTheSecondStep(decision);
        assertThat(decision.getMetadata()).containsEntry("evaluator", "ZeroTrustPolicyEvaluator");
    }

    @Test
    @DisplayName("sign-ins at once inside the ALLOW each meet the second step, while the ALLOW is written again")
    void signInsAtOnceEachMeetTheSecondStep() throws Exception {
        allowedInTheVictimsSession();
        ExecutorService pool = Executors.newFixedThreadPool(SIGN_INS_AT_ONCE + 1);
        AtomicBoolean signingIn = new AtomicBoolean(true);
        CountDownLatch start = new CountDownLatch(1);
        try {
            Future<?> writer = pool.submit(() -> {
                while (signingIn.get()) {
                    allowedInTheVictimsSession();
                }
            });
            List<Future<MfaDecision>> signIns = new ArrayList<>();
            for (int i = 0; i < SIGN_INS_AT_ONCE; i++) {
                String address = "198.51.100." + (i + 1);
                signIns.add(pool.submit(() -> {
                    start.await();
                    return policy.provider.evaluateInitialMfaRequirement(
                            SignInPolicyFixture.signIn(user, address, THIEF_BROWSER));
                }));
            }
            start.countDown();
            for (Future<MfaDecision> signIn : signIns) {
                assertAsksForTheSecondStep(signIn.get(30, TimeUnit.SECONDS));
            }
            signingIn.set(false);
            writer.get(30, TimeUnit.SECONDS);
        } finally {
            signingIn.set(false);
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("the ALLOW a passed step-up leaves in one session waives nothing for another sign-in")
    void theAllowOfAStepUpWaivesNothingElsewhere() {
        store().saveAction(user, ZeroTrustAction.CHALLENGE, Map.of());
        store().holdChallengeForOtherSessions(user, VICTIM_CONTEXT);
        store().saveActionWithPrevious(user, ZeroTrustAction.ALLOW, VICTIM_CONTEXT);
        assertThat(store().getActionFromHash(user)).as("what the password step reads").isEqualTo(ZeroTrustAction.ALLOW);

        assertAsksForTheSecondStep(policy.provider.evaluateInitialMfaRequirement(
                SignInPolicyFixture.signIn(user, THIEF_ADDRESS, THIEF_BROWSER)));
    }

    @Test
    @DisplayName("an ALLOW that ran out leaves a last verified ALLOW, which waives nothing either")
    void theLastVerifiedAllowWaivesNothing() {
        allowedInTheVictimsSession();
        analysisRunsOut(user);
        assertThat(store().getLastVerifiedAction(user)).as("the record of the last decision").isEqualTo(ZeroTrustAction.ALLOW);

        assertAsksForTheSecondStep(policy.provider.evaluateInitialMfaRequirement(
                SignInPolicyFixture.signIn(user, THIEF_ADDRESS, THIEF_BROWSER)));
    }

    @Test
    @DisplayName("a user no decision was reached for meets the second step")
    void noDecisionYet() {
        assertAsksForTheSecondStep(policy.provider.evaluateInitialMfaRequirement(
                SignInPolicyFixture.signIn(user, VICTIM_ADDRESS, VICTIM_BROWSER)));
    }

    static Stream<Arguments> restrictions() {
        return Stream.of(
                Arguments.of(ZeroTrustAction.CHALLENGE, MfaDecision.DecisionType.CHALLENGED, true),
                Arguments.of(ZeroTrustAction.BLOCK, MfaDecision.DecisionType.BLOCKED, false),
                Arguments.of(ZeroTrustAction.ESCALATE, MfaDecision.DecisionType.ESCALATED, false));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("restrictions")
    @DisplayName("a stored restriction answers the password step as it did")
    void aStoredRestrictionStands(ZeroTrustAction action, MfaDecision.DecisionType expected, boolean required) {
        store().saveAction(user, action, Map.of());

        MfaDecision decision = policy.provider.evaluateInitialMfaRequirement(
                SignInPolicyFixture.signIn(user, THIEF_ADDRESS, THIEF_BROWSER));

        assertThat(decision.getType()).isEqualTo(expected);
        assertThat(decision.isRequired()).isEqualTo(required);
    }

    @Test
    @DisplayName("the fallback evaluator reads a stored ALLOW the same way")
    void theFallbackWaivesNothingOnAStoredAllow() {
        allowedInTheVictimsSession();

        assertAsksForTheSecondStep(policy.fallback.evaluatePolicy(
                SignInPolicyFixture.signIn(user, THIEF_ADDRESS, THIEF_BROWSER)));
    }

    @Test
    @DisplayName("the action the zero trust evaluator left on the context is the stored one, and waives nothing")
    void theActionOnTheContextIsTheStoredOne() {
        allowedInTheVictimsSession();
        FactorContext context = SignInPolicyFixture.signIn(user, THIEF_ADDRESS, THIEF_BROWSER);
        policy.provider.evaluateInitialMfaRequirement(context);
        assertThat(context.getAttribute(FactorContextAttributes.Policy.ZERO_TRUST_ACTION))
                .as("the value is what the store holds, nothing decided for this sign-in")
                .isEqualTo(ZeroTrustAction.ALLOW.name());

        assertAsksForTheSecondStep(policy.fallback.evaluatePolicy(context));
    }

    @Test
    @DisplayName("an approved agent's account still signs in on its ALLOW, without the factors made for people")
    void anAgentAccountKeepsItsPolicy() {
        store().saveAction(SignInPolicyFixture.AGENT_ACCOUNT, ZeroTrustAction.ALLOW, Map.of());

        MfaDecision decision = policy.provider.evaluateInitialMfaRequirement(
                SignInPolicyFixture.signIn(SignInPolicyFixture.AGENT_ACCOUNT, THIEF_ADDRESS, THIEF_BROWSER));

        assertThat(decision.getType()).isEqualTo(MfaDecision.DecisionType.NO_MFA_REQUIRED);
        assertThat(AgentAccountMfaPolicyEvaluator.isAgentAccountDecision(decision)).isTrue();
    }

    private void allowedInTheVictimsSession() {
        store().saveAction(user, ZeroTrustAction.ALLOW, Map.of("contextBindingHash", VICTIM_CONTEXT));
    }

    static void assertAsksForTheSecondStep(MfaDecision decision) {
        assertThat(decision.getType()).as(decision.getReason()).isEqualTo(MfaDecision.DecisionType.CHALLENGED);
        assertThat(decision.isRequired()).isTrue();
        assertThat(decision.isAllowed()).isFalse();
        assertThat(decision.getFactorCount()).isPositive();
        assertThat(decision.getRequiredFactors()).containsExactly(AuthType.OTT);
    }
}
