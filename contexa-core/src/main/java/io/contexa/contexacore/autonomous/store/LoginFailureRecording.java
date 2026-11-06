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
package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Stores a failed sign-in once per request. The same failure reaches the store from the authentication failure event,
 * the failure handler and the login policy; the first of them stores it and marks the request, so the user's count says
 * how many times the user failed, not how many paths saw the failure. Outside a request every call stores.
 * <p>
 * A failed sign-in names whoever the client typed, so a store keeps of them only as much as the limits here say, the same
 * in every store: a flood of names nobody has fills a fixed size and goes with its window.
 */
@Slf4j
public final class LoginFailureRecording {

    /**
     * How many names and addresses a store keeps failures for. Past it the keys written the longest ago go, and for a
     * window a name without a record reads as not known, never as no failures: pushing a name out hides nothing as zero.
     */
    public static final int MAX_KEYS = 10_000;

    /**
     * How many failures a key keeps, the latest ones: the count of one name stops here, twice the count at which the
     * decisions read a name as abused. With {@link #MAX_KEYS} it bounds what the worst flood holds: two million failures,
     * some 100 MB in memory.
     */
    public static final int MAX_PER_KEY = 200;

    /** The longest name kept: a request can carry megabytes of one, and no account has such a name. */
    static final int MAX_NAME_LENGTH = 256;

    private static final String RECORDED_USER_ATTRIBUTE = LoginFailureRecording.class.getName() + ".user";

    private static final AtomicLong NEXT_LOSS_REPORT_AT = new AtomicLong();

    private LoginFailureRecording() {
    }

    /** Stores the failure at the current request's observed time, the clock failures are counted on; else the server's. */
    public static void recordOnce(SecurityContextDataStore store, String userId, String clientIp) {
        recordOnce(store, userId, clientIp, requestTimeMillis());
    }

    public static void recordOnce(SecurityContextDataStore store, String userId, String clientIp, long failedAtMs) {
        if (store == null) {
            return;
        }
        String name = userId != null && userId.length() <= MAX_NAME_LENGTH ? userId : null;
        HttpServletRequest request = currentRequest();
        if (request != null && StringUtils.hasText(name)) {
            String user = name.trim();
            if (user.equals(request.getAttribute(RECORDED_USER_ATTRIBUTE))) {
                return;
            }
            request.setAttribute(RECORDED_USER_ATTRIBUTE, user);
        }
        store.recordLoginFailure(ZeroTrustUserKey.person(name), clientIp, failedAtMs);
    }

    /**
     * What a store files the failures of a user's key under: every spelling of a name is one person, as for a decision
     * of the name, so that a case changed from one guess to the next does not start the count again.
     */
    static String subject(String userKey) {
        return ZeroTrustUserKey.of(userKey.trim());
    }

    /** Says once a window that a store let go of failures to keep within {@link #MAX_KEYS}. */
    static void reportLoss(long nowMs, Duration window) {
        long due = NEXT_LOSS_REPORT_AT.get();
        if (nowMs >= due && NEXT_LOSS_REPORT_AT.compareAndSet(due, nowMs + window.toMillis())) {
            log.error("[Contexa] Failed sign-ins came in under more than {} names and addresses within {} minutes. Decisions "
                    + "read a name that was let go of as not known, not as no failures. This takes someone trying names in "
                    + "bulk", MAX_KEYS, window.toMinutes());
        }
    }

    private static long requestTimeMillis() {
        HttpServletRequest request = currentRequest();
        Instant observedAt = request != null ? RequestInfoExtractor.extractObservedAt(request) : null;
        return observedAt != null ? observedAt.toEpochMilli() : System.currentTimeMillis();
    }

    private static HttpServletRequest currentRequest() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                ? attributes.getRequest()
                : null;
    }
}
