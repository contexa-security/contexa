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
package io.contexa.contexacore.autonomous.execution;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacore.autonomous.execution.ZeroTrustExceptionHandler.ZeroTrustErrorResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A CHALLENGE decided inside the request (a synchronous {@code @Protectable}) starts the step-up flow before the answer
 * goes out, so the user can step up at once, as with a CHALLENGE the request filters enforce; every other answer stays
 * as it was.
 */
class ZeroTrustExceptionHandlerTest {

    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/projects/GB-500/exports");
    private final MockHttpServletResponse response = new MockHttpServletResponse();
    private final AtomicInteger starts = new AtomicInteger();

    private ZeroTrustChallengeFlowStarter starter(Optional<String> mfaUrl) {
        return (req, res) -> {
            starts.incrementAndGet();
            return mfaUrl;
        };
    }

    @Test
    @DisplayName("동기 판정의 CHALLENGE는 응답 전에 본인 확인 절차를 시작하고 이어 갈 주소를 함께 보낸다")
    void aChallengeDecidedInTheRequestStartsTheStepUpFlow() {
        ZeroTrustExceptionHandler handler = new ZeroTrustExceptionHandler(starter(Optional.of("/mfa/select-factor")));

        ResponseEntity<ZeroTrustErrorResponse> answer = handler.handleZeroTrustDenied(
                ZeroTrustAccessDeniedException.challengeRequired("PaymentService.process"), request, response);

        assertThat(starts).hasValue(1);
        assertThat(answer.getStatusCode().value()).isEqualTo(401);
        assertThat(answer.getBody().getCode()).isEqualTo("ZERO_TRUST_CHALLENGE");
        assertThat(answer.getBody().getMfaUrl()).isEqualTo("/mfa/select-factor");
    }

    @Test
    @DisplayName("CHALLENGE가 아닌 판정은 본인 확인 절차를 시작하지 않고 응답도 그대로다")
    void otherDecisionsDoNotStartIt() throws Exception {
        ZeroTrustExceptionHandler handler = new ZeroTrustExceptionHandler(starter(Optional.of("/mfa/select-factor")));

        ResponseEntity<ZeroTrustErrorResponse> blocked = handler.handleZeroTrustDenied(
                ZeroTrustAccessDeniedException.blocked("PaymentService.process"), request, response);
        ResponseEntity<ZeroTrustErrorResponse> review = handler.handleZeroTrustDenied(
                ZeroTrustAccessDeniedException.pendingReview("PaymentService.process"), request, response);

        assertThat(starts).hasValue(0);
        assertThat(blocked.getBody().getMfaUrl()).isNull();
        assertThat(review.getBody().getMfaUrl()).isNull();
        String json = new ObjectMapper().registerModule(new JavaTimeModule()).writeValueAsString(blocked.getBody());
        assertThat(json).as("the answer keeps its former fields only").doesNotContain("mfaUrl");
    }

    @Test
    @DisplayName("시작 장치가 없거나, 시작하지 못했거나, 실패해도 응답은 이전과 같다")
    void theAnswerStaysAsItWasWhenNothingStarts() {
        ZeroTrustAccessDeniedException challenge = ZeroTrustAccessDeniedException.challengeRequired("Payment");

        assertThat(new ZeroTrustExceptionHandler().handleZeroTrustDenied(challenge, request, response).getBody()
                .getMfaUrl()).as("no starter").isNull();
        assertThat(new ZeroTrustExceptionHandler(starter(Optional.empty()))
                .handleZeroTrustDenied(challenge, request, response).getBody().getMfaUrl())
                .as("a start already in progress").isNull();
        ResponseEntity<ZeroTrustErrorResponse> failed = new ZeroTrustExceptionHandler((req, res) -> {
            throw new IllegalStateException("flow store unavailable");
        }).handleZeroTrustDenied(challenge, request, response);
        assertThat(failed.getStatusCode().value()).isEqualTo(401);
        assertThat(failed.getBody().getMfaUrl()).as("a failing starter").isNull();
    }
}
