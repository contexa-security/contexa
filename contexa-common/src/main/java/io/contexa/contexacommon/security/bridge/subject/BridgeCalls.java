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
package io.contexa.contexacommon.security.bridge.subject;

import io.contexa.contexacommon.security.bridge.subject.ContexaBridgeResult.Outcome;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

/**
 * How {@link ContexaBridge} and {@link ContexaUsers} reach the handler Contexa registered when it started: nothing the
 * handler does may fail the application's request, and a failure that repeats on every call is told once a minute at most.
 */
@Slf4j
final class BridgeCalls {

    private static final long REPORT_INTERVAL_MILLIS = 60_000L;
    private static final AtomicLong FAILURES = new AtomicLong();
    private static final AtomicLong LAST_REPORT = new AtomicLong();

    private BridgeCalls() {
    }

    /** The user id the application passed, without the spaces around it, or {@code null} when it breaks the rules of one. */
    @Nullable
    static String userId(@Nullable String userId) {
        if (userId == null) {
            return null;
        }
        ContexaSubject subject = ContexaSubject.of(userId, null).build();
        return subject.hasUserId() ? subject.getUserId() : null;
    }

    static <H> ContexaBridgeResult call(@Nullable H handler, String what, Function<H, ContexaBridgeResult> call) {
        if (handler == null) {
            return ContexaBridgeResult.of(Outcome.NOT_INITIALIZED, "Contexa has not started");
        }
        try {
            ContexaBridgeResult result = call.apply(handler);
            if (result == null) {
                report(what, "the handler answered nothing", null);
                return ContexaBridgeResult.of(Outcome.FAILED, "the handler answered nothing");
            }
            return result;
        } catch (Exception | LinkageError | StackOverflowError failure) {
            report(what, failure.getClass().getSimpleName(), failure);
            return ContexaBridgeResult.of(Outcome.FAILED, failure.getClass().getSimpleName());
        }
    }

    static ContexaBridgeResult invalid(String reason) {
        return ContexaBridgeResult.of(Outcome.INVALID, reason);
    }

    private static void report(String what, String reason, @Nullable Throwable failure) {
        long now = System.currentTimeMillis();
        long count = FAILURES.incrementAndGet();
        long last = LAST_REPORT.get();
        if (now - last < REPORT_INTERVAL_MILLIS || !LAST_REPORT.compareAndSet(last, now)) {
            return;
        }
        if (failure != null) {
            log.error("[Bridge] Contexa could not take the application's {} ({}) and let the request go on ({} so far)",
                    what, reason, count, failure);
        } else {
            log.error("[Bridge] Contexa could not take the application's {} ({}) and let the request go on ({} so far)",
                    what, reason, count);
        }
    }
}
