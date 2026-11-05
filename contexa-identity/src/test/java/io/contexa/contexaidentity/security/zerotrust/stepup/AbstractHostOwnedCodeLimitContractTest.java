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
package io.contexa.contexaidentity.security.zerotrust.stepup;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.zerotrust.ChallengeResolution;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.ott.DefaultOneTimeToken;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * How many answers a one-time code of the step-up gets, the same on both stores. The answers are counted for the session
 * context: a stolen cookie is another address or browser, so its wrong answers use up its own, and what is discarded at
 * the limit is what that context asked for. Each case takes a user of its own, so the Redis case runs beside others.
 */
abstract class AbstractHostOwnedCodeLimitContractTest {

    private static final int LIMIT = 5;
    private static final int ANSWERS_AT_ONCE = 20;

    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final ChallengeResolution resolution = mock(ChallengeResolution.class);
    private final UserRepository users = mock(UserRepository.class);
    private final EmailService email = mock(EmailService.class);
    private final MailedCodes mailed = new MailedCodes();
    private final MockHttpServletRequest victim = session("203.0.113.10", "Mozilla/5.0 (victim)");
    private final MockHttpServletRequest thief = session("198.51.100.77", "curl/8.5.0 (thief)");

    private Authentication signedIn;
    private long userId;
    private HostOwnedStepUpService service;

    /** The store under test. */
    protected abstract StepUpOptionsStore store();

    @BeforeEach
    void aUserUnderAChallenge() {
        assertThat(store()).as("the store under test").isNotNull();
        String name = "limit-" + UUID.randomUUID();
        userId = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        signedIn = new TestingAuthenticationToken(name, null, "ROLE_USER");
        Users user = mock(Users.class);
        when(user.getId()).thenReturn(userId);
        when(user.getUsername()).thenReturn("brg_" + name);
        when(user.getEmail()).thenReturn("alice@corp.example");
        when(users.findByExternalSubjectIdAndBridgeManagedTrue(name)).thenReturn(List.of(user));
        when(actions.getCurrentAction(eq(name), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(email.isMailSenderConfigured()).thenReturn(true);
        when(resolution.releaseChallenge(anyString(), any(), any(), any())).thenReturn(true);
        service = new HostOwnedStepUpService(actions, resolution, users, "shadow.contexa.local", store(), mailed, email,
                null, null, null, null, null, LIMIT);
    }

    private static MockHttpServletRequest session(String address, String browser) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/step-up/code/verify");
        request.setRequestedSessionId("the-session-of-the-cookie");
        request.setRemoteAddr(address);
        request.addHeader("User-Agent", browser);
        return request;
    }

    private HostOwnedStepUpService.CodeSending askForACode(MockHttpServletRequest context) {
        return service.sendCode(context, signedIn);
    }

    private boolean answer(MockHttpServletRequest context, String code) {
        return service.verifyCode(context, signedIn, code);
    }

    private void wrongAnswers(MockHttpServletRequest context, int answers) {
        for (int i = 0; i < answers; i++) {
            assertThat(answer(context, "wrong-" + i)).isFalse();
        }
    }

    /** The wait between two mails has passed. */
    private void theWaitIsOver() {
        store().release("code-sent:" + userId);
    }

    @Test
    @DisplayName("once the answers are used up the code is refused, right as it is")
    void theRightCodeIsRefusedAfterTheLimit() {
        askForACode(victim);
        String code = mailed.newest();

        wrongAnswers(victim, LIMIT);

        assertThat(answer(victim, code)).isFalse();
        verify(resolution, never()).releaseChallenge(anyString(), any(), any(), any());
    }

    @Test
    @DisplayName("the answer before the limit still counts: the right code passes after one wrong answer less")
    void theLastAnswerStillCounts() {
        askForACode(victim);

        wrongAnswers(victim, LIMIT - 1);

        assertThat(answer(victim, mailed.newest())).isTrue();
        verify(resolution).releaseChallenge(anyString(), any(), any(), any());
    }

    @Test
    @DisplayName("forty wrong answers leave the code as refused as the limit does, and no code is looked at past the limit")
    void wrongAnswersPastTheLimitChangeNothing() {
        askForACode(victim);
        String code = mailed.newest();

        wrongAnswers(victim, 40);

        assertThat(answer(victim, code)).isFalse();
        assertThat(mailed.looks()).isLessThanOrEqualTo(LIMIT);
    }

    @Test
    @DisplayName("a passed code clears the count: a code still good gets every answer again, with no mail in between")
    void aPassedCodeClearsTheCount() {
        askForACode(victim);
        String stillGood = mailed.newest();
        theWaitIsOver();
        askForACode(victim);
        wrongAnswers(victim, LIMIT - 1);
        assertThat(answer(victim, mailed.newest())).isTrue();

        wrongAnswers(victim, LIMIT - 1);

        assertThat(answer(victim, stillGood)).isTrue();
    }

    @Test
    @DisplayName("a context that asked for no code lifts no wait: wrong answers alone mail nothing")
    void aContextWithoutACodeLiftsNoWait() {
        askForACode(victim);

        wrongAnswers(thief, LIMIT);

        assertThat(askForACode(thief)).isEqualTo(HostOwnedStepUpService.CodeSending.TOO_SOON);
        verify(email, times(1)).sendHtmlMessage(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("past the limit a new code is mailed at once, and it passes while the old one stays refused")
    void aNewCodeRecoversAtOnce() {
        assertThat(askForACode(victim)).isEqualTo(HostOwnedStepUpService.CodeSending.SENT);
        String discarded = mailed.newest();
        wrongAnswers(victim, LIMIT);

        assertThat(askForACode(victim)).as("the wait between mails stands in nobody's way here")
                .isEqualTo(HostOwnedStepUpService.CodeSending.SENT);

        assertThat(answer(victim, discarded)).isFalse();
        assertThat(answer(victim, mailed.newest())).isTrue();
    }

    @Test
    @DisplayName("the wait between mails is lifted once: wrong answers do not fill the mailbox")
    void theWaitIsLiftedOnce() {
        askForACode(victim);
        wrongAnswers(victim, LIMIT);
        assertThat(askForACode(victim)).isEqualTo(HostOwnedStepUpService.CodeSending.SENT);
        wrongAnswers(victim, LIMIT);

        assertThat(askForACode(victim)).isEqualTo(HostOwnedStepUpService.CodeSending.TOO_SOON);

        verify(email, times(2)).sendHtmlMessage(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("a code asked for too soon leaves the answers used up: only a mailed code gives them back")
    void aCodeNotMailedGivesNoAnswersBack() {
        askForACode(victim);
        String code = mailed.newest();
        assertThat(askForACode(victim)).isEqualTo(HostOwnedStepUpService.CodeSending.TOO_SOON);

        wrongAnswers(victim, LIMIT - 1);

        assertThat(askForACode(victim)).isEqualTo(HostOwnedStepUpService.CodeSending.TOO_SOON);
        wrongAnswers(victim, 1);
        assertThat(answer(victim, code)).isFalse();
    }

    @Test
    @DisplayName("answers at once pass no limit: no more codes are looked at than there are answers")
    void answersAtOncePassNoLimit() throws Exception {
        askForACode(victim);
        String code = mailed.newest();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService callers = Executors.newFixedThreadPool(ANSWERS_AT_ONCE);
        try {
            List<Future<Boolean>> answers = new ArrayList<>();
            for (int i = 0; i < ANSWERS_AT_ONCE; i++) {
                int attempt = i;
                answers.add(callers.submit(() -> {
                    start.await();
                    return answer(victim, "wrong-" + attempt);
                }));
            }
            start.countDown();
            for (Future<Boolean> answered : answers) {
                assertThat(answered.get()).isFalse();
            }
        } finally {
            callers.shutdownNow();
        }

        assertThat(mailed.looks()).isEqualTo(LIMIT);
        assertThat(answer(victim, code)).isFalse();
    }

    @Test
    @DisplayName("a thief's wrong answers use up the thief's own: the victim's code stays good in the victim's session")
    void aThiefsWrongAnswersLeaveTheVictimsCode() {
        askForACode(victim);
        String code = mailed.newest();

        wrongAnswers(thief, LIMIT + 3);

        assertThat(answer(thief, code)).as("the thief is out of answers").isFalse();
        assertThat(answer(victim, code)).isTrue();
    }

    @Test
    @DisplayName("a thief's wrong answers take none of the victim's answers")
    void aThiefTakesNoneOfTheVictimsAnswers() {
        askForACode(victim);
        wrongAnswers(thief, LIMIT);

        wrongAnswers(victim, LIMIT - 1);

        assertThat(answer(victim, mailed.newest())).isTrue();
    }

    @Test
    @DisplayName("a code the thief asked for is discarded with the thief's answers; the victim gets a new one and passes")
    void aThiefsOwnCodeIsDiscardedAndTheVictimRecovers() {
        askForACode(thief);
        String mailedToTheVictim = mailed.newest();
        wrongAnswers(thief, LIMIT);

        assertThat(answer(victim, mailedToTheVictim)).as("the code the thief spoiled").isFalse();

        assertThat(askForACode(victim)).isEqualTo(HostOwnedStepUpService.CodeSending.SENT);
        assertThat(answer(victim, mailed.newest())).isTrue();
    }

    @Test
    @DisplayName("a thief who goes on answering spoils no code the victim asked for afterwards")
    void aThiefGoingOnSpoilsNoNewCode() {
        askForACode(thief);
        wrongAnswers(thief, LIMIT);
        askForACode(victim);
        String code = mailed.newest();

        wrongAnswers(thief, LIMIT * 3);

        assertThat(answer(victim, code)).isTrue();
    }

    @Test
    @DisplayName("the answer past the limit is the answer to any wrong code: nothing tells the limit from a typing error")
    void theAnswerSaysNothingOfTheLimit() {
        HostOwnedStepUpController controller = new HostOwnedStepUpController(service);
        SecurityContextHolder.getContext().setAuthentication(signedIn);
        try {
            askForACode(victim);
            ResponseEntity<Map<String, Object>> first = controller.verifyCode(victim, "wrong");
            wrongAnswers(victim, LIMIT);
            ResponseEntity<Map<String, Object>> pastTheLimit = controller.verifyCode(victim, mailed.newest());

            assertThat(pastTheLimit.getStatusCode()).isEqualTo(first.getStatusCode());
            assertThat(pastTheLimit.getBody()).isEqualTo(first.getBody());
            assertThat(pastTheLimit.getHeaders()).isEqualTo(first.getHeaders());
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    /** The codes as {@code JdbcOneTimeTokenService} keeps them: a value for a user, gone once it is read. */
    private static final class MailedCodes implements OneTimeTokenService {

        private final Map<String, OneTimeToken> live = new ConcurrentHashMap<>();
        private final AtomicInteger looks = new AtomicInteger();
        private volatile String newest;

        @Override
        public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
            OneTimeToken token = new DefaultOneTimeToken(UUID.randomUUID().toString(), request.getUsername(),
                    Instant.now().plusSeconds(300));
            live.put(token.getTokenValue(), token);
            newest = token.getTokenValue();
            return token;
        }

        @Override
        public OneTimeToken consume(OneTimeTokenAuthenticationToken authentication) {
            looks.incrementAndGet();
            return live.remove(authentication.getTokenValue());
        }

        private String newest() {
            return newest;
        }

        private int looks() {
            return looks.get();
        }
    }
}
