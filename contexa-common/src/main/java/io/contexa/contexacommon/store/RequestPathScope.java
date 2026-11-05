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
package io.contexa.contexacommon.store;

import org.springframework.web.context.request.RequestContextHolder;

/**
 * Where a thread is, for what a store may cost it. A thread serving a request waits about a second for a store that does
 * not answer, because the application's request is waiting behind it; the engine's own threads keep the waits they rely
 * on. Inside a protected call Contexa's own work is bounded further, up to the application's method, which is the
 * application's own business however long it takes.
 */
public final class RequestPathScope {

    private static final ThreadLocal<Integer> DEPTH = ThreadLocal.withInitial(() -> 0);

    private RequestPathScope() {
    }

    /** Whether this thread serves an application's request. */
    public static boolean onRequestThread() {
        return RequestContextHolder.getRequestAttributes() != null;
    }

    /** Whether this thread is in Contexa's own work of a protected call. */
    public static boolean inContexaWork() {
        return DEPTH.get() > 0;
    }

    /** Contexa's own work of a protected call starts here; {@link #leave()} ends it. */
    public static void enter() {
        DEPTH.set(DEPTH.get() + 1);
    }

    public static void leave() {
        int depth = DEPTH.get() - 1;
        if (depth > 0) {
            DEPTH.set(depth);
        } else {
            DEPTH.remove();
        }
    }

    /** The application's method runs from here until {@link #resume(int)}; returns what to resume with. */
    public static int suspend() {
        int depth = DEPTH.get();
        DEPTH.remove();
        return depth;
    }

    public static void resume(int depth) {
        if (depth > 0) {
            DEPTH.set(depth);
        } else {
            DEPTH.remove();
        }
    }
}
