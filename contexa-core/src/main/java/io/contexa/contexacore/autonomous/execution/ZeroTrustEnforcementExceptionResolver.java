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

import com.fasterxml.jackson.core.json.JsonWriteFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacore.autonomous.execution.ZeroTrustExceptionHandler.ZeroTrustErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Answers the zero-trust decisions made at a protected method before any exception handler of the application can.
 * {@link ZeroTrustExceptionHandler} comes first among advices only as far as an order can put it: an application's advice
 * of the same order goes ahead of it by bean order and a handler inside a controller goes ahead of every advice, and a
 * catch-all of theirs then turns a CHALLENGE into its own 200 and a BLOCK into a response the cut ends (PR-47). A resolver
 * runs ahead of all of those; {@link PriorityOrdered} puts this one ahead of an application's resolver of the same order.
 * <p>
 * The answer is that handler's. It is written here rather than through the application's message converters: what the
 * client accepts, the application's JSON naming or an advice over its bodies do not decide what a refusal says, and a
 * write that failed there would hand the exception to the very handlers it must not reach. Every other exception is left
 * to the application.
 */
@Slf4j
public class ZeroTrustEnforcementExceptionResolver implements HandlerExceptionResolver, PriorityOrdered {

    private static final int MAX_CAUSES = 16;
    /** ASCII only: a controller that opened the writer leaves its charset, which is no longer this class's to set. */
    private static final ObjectMapper ANSWERS = JsonMapper.builder()
            .addModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .enable(JsonWriteFeature.ESCAPE_NON_ASCII)
            .build();

    private final ZeroTrustExceptionHandler answers;

    public ZeroTrustEnforcementExceptionResolver(ZeroTrustExceptionHandler answers) {
        this.answers = answers;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object handler,
                                         Exception exception) {
        RuntimeException decision = decisionIn(exception);
        if (decision == null) {
            return null;
        }
        try {
            ResponseEntity<ZeroTrustErrorResponse> answer = answerTo(decision, request, response);
            if (answer != null) {
                write(answer, response);
            }
        } catch (IOException | RuntimeException failed) {
            // The refusal stands all the same: without a body, and still kept from the application's handlers.
            log.error("Could not write the answer of a zero-trust decision: {}", decision.getMessage(), failed);
            if (!response.isCommitted()) {
                response.setStatus(statusOf(decision));
            }
        }
        return new ModelAndView();
    }

    /** The decision the exception is or carries; Spring's own matching of a handler looks into the causes too. */
    private static RuntimeException decisionIn(Exception exception) {
        Throwable current = exception;
        for (int depth = 0; current != null && depth < MAX_CAUSES; depth++) {
            if (current instanceof ZeroTrustAccessDeniedException || current instanceof AnomalyDetectedException
                    || current instanceof RapidProtectableReentryDeniedException) {
                return (RuntimeException) current;
            }
            current = current.getCause();
        }
        return null;
    }

    private ResponseEntity<ZeroTrustErrorResponse> answerTo(RuntimeException decision, HttpServletRequest request,
                                                            HttpServletResponse response) {
        if (decision instanceof ZeroTrustAccessDeniedException denied) {
            return answers.handleZeroTrustDenied(denied, request, response);
        }
        if (decision instanceof AnomalyDetectedException anomaly) {
            return answers.handleAnomalyDetected(anomaly, response);
        }
        return answers.handleRapidProtectableReentryDenied((RapidProtectableReentryDeniedException) decision, response);
    }

    private static void write(ResponseEntity<ZeroTrustErrorResponse> answer, HttpServletResponse response) throws IOException {
        response.setStatus(answer.getStatusCode().value());
        answer.getHeaders().forEach((name, values) -> values.forEach(value -> response.addHeader(name, value)));
        if (answer.getBody() == null) {
            return;
        }
        byte[] body = ANSWERS.writeValueAsBytes(answer.getBody());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setContentLength(body.length);
        try {
            response.getOutputStream().write(body);
        } catch (IllegalStateException writerOpened) {
            response.getWriter().write(new String(body, StandardCharsets.US_ASCII));
        }
    }

    private static int statusOf(RuntimeException decision) {
        if (decision instanceof ZeroTrustAccessDeniedException denied) {
            return denied.getHttpStatus();
        }
        if (decision instanceof RapidProtectableReentryDeniedException reentry) {
            return reentry.getHttpStatus();
        }
        return HttpServletResponse.SC_FORBIDDEN;
    }
}
