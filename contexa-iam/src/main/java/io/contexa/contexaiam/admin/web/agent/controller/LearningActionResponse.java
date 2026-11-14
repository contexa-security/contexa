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
package io.contexa.contexaiam.admin.web.agent.controller;

import io.contexa.contexacore.autonomous.agent.AgentLearningControl;
import io.contexa.contexaiam.admin.web.agent.service.AgentLearningAdminService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** What was done, or why it was not. */
public record LearningActionResponse(boolean success, String action, String agentId, String delegationId,
                                     int records, int baselines, int observations, String error) {

    static LearningActionResponse done(AgentLearningControl.Outcome outcome) {
        return new LearningActionResponse(true, outcome.action(), outcome.agentId(), outcome.delegationId(),
                outcome.records(), outcome.baselines(), outcome.observations(), null);
    }

    static LearningActionResponse failed(String error) {
        return new LearningActionResponse(false, null, null, null, 0, 0, 0, error);
    }
}
