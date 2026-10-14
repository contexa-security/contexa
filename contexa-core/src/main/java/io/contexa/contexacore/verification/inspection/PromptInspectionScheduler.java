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
package io.contexa.contexacore.verification.inspection;

import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.Objects;

/**
 * The automatic inspection: every interval the scheduler's thread inspects the oldest uninspected sealed packages, up
 * to the batch, under one lock across instances. No decision thread runs it.
 */
public class PromptInspectionScheduler {

    public static final String LOCK_NAME = "promptInspectionRound";

    /** The round's default interval and first delay, which the settings class starts from too. */
    public static final String DEFAULT_INTERVAL = "PT30S";

    public static final String DEFAULT_INITIAL_DELAY = "PT30S";

    private final PromptInspectionService service;
    private final int batchSize;
    private final int samplePercent;

    public PromptInspectionScheduler(PromptInspectionService service, int batchSize, int samplePercent) {
        this.service = Objects.requireNonNull(service, "service");
        if (batchSize < 1) {
            throw new IllegalArgumentException("batchSize must be at least 1");
        }
        if (samplePercent < 1 || samplePercent > 100) {
            throw new IllegalArgumentException("samplePercent must be between 1 and 100");
        }
        this.batchSize = batchSize;
        this.samplePercent = samplePercent;
    }

    @Scheduled(fixedDelayString = "${contexa.prompt-inspection.interval:" + DEFAULT_INTERVAL + "}",
            initialDelayString = "${contexa.prompt-inspection.initial-delay:" + DEFAULT_INITIAL_DELAY + "}")
    @SchedulerLock(name = LOCK_NAME, lockAtMostFor = "PT10M", lockAtLeastFor = "PT5S")
    public void inspectUninspected() {
        service.inspectUninspected(batchSize, samplePercent);
    }
}
