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

/**
 * The admin API of what an agent learned (docs/agent A3-8): whether the learning of an agent, or of one of its
 * delegations, is quarantined, and the quarantine, release or removal of it. The agent is named in the query or the
 * body, as on the console, because agent identifiers may hold any character.
 */
@Slf4j
@RestController
@RequestMapping("/contexa/admin/api/agents/learning")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AgentLearningApiController {

    /** The learning state of an agent or of one of its delegations. */
    public record LearningState(String agentId, String delegationId, boolean quarantined) {
    }

    /** An action on the learning: quarantine, release or remove, with the administrator's reason. */
    public record LearningActionRequest(String agentId, String delegationId, String action, String reason) {
    }

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

    /** What the administrator is told of a fault of the server; the exception is in the log. */
    private static final String SERVER_FAULT_MESSAGE = "The action could not be completed. See the server log.";

    private final AgentLearningAdminService learningService;

    public AgentLearningApiController(AgentLearningAdminService learningService) {
        this.learningService = learningService;
    }

    @GetMapping
    public ResponseEntity<LearningState> state(@RequestParam("agentId") String agentId,
                                               @RequestParam(value = "delegationId", required = false)
                                               String delegationId) {
        if (agentId.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(new LearningState(agentId.trim(), delegationId,
                learningService.quarantined(agentId, delegationId)));
    }

    @PostMapping
    public ResponseEntity<LearningActionResponse> act(@RequestBody(required = false) LearningActionRequest request) {
        if (request == null || request.agentId() == null || request.agentId().isBlank()) {
            return ResponseEntity.badRequest().body(LearningActionResponse.failed("agentId is required"));
        }
        if (!learningService.available()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(LearningActionResponse.failed("the autonomous security plane is off"));
        }
        AgentLearningAdminService.Action action;
        try {
            action = AgentLearningAdminService.Action.of(request.action());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(LearningActionResponse.failed(e.getMessage()));
        }
        if (request.reason() == null || request.reason().isBlank()) {
            return ResponseEntity.badRequest().body(LearningActionResponse.failed("reason is required"));
        }
        try {
            return ResponseEntity.ok(LearningActionResponse.done(learningService.apply(action, request.agentId(),
                    request.delegationId(), request.reason(), currentAdmin())));
        } catch (RuntimeException e) {
            log.error("[AgentLearningApi] Agent learning action failed: agentId={}, action={}", request.agentId(),
                    action, e);
            return ResponseEntity.internalServerError().body(LearningActionResponse.failed(SERVER_FAULT_MESSAGE));
        }
    }

    private static String currentAdmin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            throw new IllegalStateException("No administrator is signed in");
        }
        return authentication.getName();
    }
}
