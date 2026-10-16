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
package io.contexa.contexacore.verification.capture;

import io.contexa.contexacommon.domain.SecurityEvent;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;

import java.util.Objects;
import java.util.function.Consumer;

/**
 * W6-6 (P6-CHANGE-4): completes the prompt trace after Layer2. A Layer2 that drew its own prompt (a second pass, or a
 * first pass without a model verdict) left it pending; completing it makes the seal hold the applied stage's prompt.
 * A Layer2 that asked no model left nothing pending, and the Layer1 snapshot stays.
 */
@Aspect
@Slf4j
public class SealedEvidenceLayer2CompletionAspect {

    private final Consumer<SecurityEvent> traceCompleter;

    public SealedEvidenceLayer2CompletionAspect(SealedEvidencePromptTraceStore traceStore) {
        this(Objects.requireNonNull(traceStore, "traceStore must not be null")::complete);
    }

    SealedEvidenceLayer2CompletionAspect(Consumer<SecurityEvent> traceCompleter) {
        this.traceCompleter = Objects.requireNonNull(traceCompleter, "traceCompleter must not be null");
    }

    @AfterReturning(
            pointcut = "execution(* io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy.evaluate(..)) && args(event)")
    public void completeAfterLayer2(SecurityEvent event) {
        if (event == null) {
            return;
        }
        try {
            traceCompleter.accept(event);
        } catch (Exception e) {
            log.error("[SealedEvidence] Failed to complete prompt trace after Layer2: eventId={}",
                    event.getEventId(), e);
        }
    }
}
