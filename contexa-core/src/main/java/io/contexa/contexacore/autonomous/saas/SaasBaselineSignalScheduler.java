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
package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;

public class SaasBaselineSignalScheduler {

    private final BaselineSignalAggregationService aggregationService;
    private final SaasBaselineSignalDispatcher dispatcher;
    private final SaasForwardingProperties properties;

    public SaasBaselineSignalScheduler(
            BaselineSignalAggregationService aggregationService,
            SaasBaselineSignalDispatcher dispatcher,
            SaasForwardingProperties properties) {
        this.aggregationService = aggregationService;
        this.dispatcher = dispatcher;
        this.properties = properties;
    }

    @Scheduled(
            initialDelayString = "${contexa.saas.baseline-signal.initial-delay-ms:300000}",
            fixedDelayString = "${contexa.saas.baseline-signal.publish-interval-ms:86400000}")
    @SchedulerLock(name = "saasBaselineSignal", lockAtMostFor = "PT15M", lockAtLeastFor = "PT30S")
    public void captureAndDispatch() {
        if (!properties.isEnabled()
                || properties.getBaselineSignal() == null
                || !properties.getBaselineSignal().isEnabled()) {
            return;
        }
        aggregationService.captureCurrentPeriod();
        dispatcher.dispatchPendingBatch();
    }
}
