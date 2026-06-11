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

public class SaasThreatKnowledgePackPullScheduler {

    private final SaasThreatKnowledgePackService threatKnowledgePackService;
    private final SaasForwardingProperties properties;

    public SaasThreatKnowledgePackPullScheduler(
            SaasThreatKnowledgePackService threatKnowledgePackService,
            SaasForwardingProperties properties) {
        this.threatKnowledgePackService = threatKnowledgePackService;
        this.properties = properties;
    }

    @Scheduled(
            initialDelayString = "${contexa.saas.threat-knowledge.initial-delay-ms:0}",
            fixedDelayString = "${contexa.saas.threat-knowledge.pull-interval-ms:3600000}")
    @SchedulerLock(name = "saasThreatKnowledgePackPull", lockAtMostFor = "PT10M", lockAtLeastFor = "PT10S")
    public void refreshThreatKnowledgePack() {
        if (!properties.isEnabled()
                || properties.getThreatKnowledge() == null
                || !properties.getThreatKnowledge().isEnabled()) {
            return;
        }
        threatKnowledgePackService.refresh();
    }
}