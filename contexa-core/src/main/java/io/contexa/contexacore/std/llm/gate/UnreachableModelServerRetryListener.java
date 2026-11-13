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
package io.contexa.contexacore.std.llm.gate;

import lombok.extern.slf4j.Slf4j;
import org.springframework.retry.RetryCallback;
import org.springframework.retry.RetryContext;
import org.springframework.retry.RetryListener;

/**
 * Ends the model client's own retry (Spring AI's RetryTemplate) at once for a model call of Contexa whose server cannot
 * be reached: the connection was refused, the host is unknown or unroutable. Without it a stopped model server held a
 * Contexa request for minutes (2 s, 10 s, 50 s, 180 s between attempts, then Contexa's own time limit and fallback).
 * <p>
 * Any other failure keeps the retry as configured (spring.ai.retry), and so does every call the application makes
 * itself: the listener acts only on the thread of a Contexa model call ({@link ModelCallScope}).
 */
@Slf4j
public final class UnreachableModelServerRetryListener implements RetryListener {

    @Override
    public <T, E extends Throwable> void onError(RetryContext context, RetryCallback<T, E> callback, Throwable throwable) {
        if (ModelCallScope.active() && ModelServerSignals.isUnreachable(throwable)) {
            log.debug("[ModelCall] Model server unreachable; no further attempt: {}", throwable.getMessage());
            context.setExhaustedOnly();
        }
    }
}
