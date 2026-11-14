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

import java.util.Locale;
import io.contexa.contexacore.autonomous.agent.AgentRegistration;
import io.contexa.contexaiam.admin.web.agent.service.AgentContainmentAdminService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * The admin API of agent stops (docs/agent A5-3): the stopped agents and delegations, their release and the kill
 * switch. The console's agent stops (AM-4) take the same actions. Every action needs a reason and is audited.
 */
@RestController
@RequestMapping("/contexa/admin/api/agents/stops")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AgentStopApiController {

    private final AgentContainmentAdminService stops;

    public AgentStopApiController(AgentContainmentAdminService stops) {
        this.stops = stops;
    }

    @GetMapping
    public ResponseEntity<Stops> stops() {
        return ResponseEntity.ok(new Stops(stops.suspendedAgents(), stops.stoppedDelegations()));
    }

    @PostMapping
    public ResponseEntity<StopResult> act(@RequestBody(required = false) StopAction request,
                                          Authentication authentication) {
        if (request == null || request.action() == null || blank(request.reason())) {
            return ResponseEntity.badRequest().body(new StopResult(false, null, List.of(),
                    "an action and a reason are required"));
        }
        if (!stops.available()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(new StopResult(false,
                    request.action(), List.of(), "the autonomous security plane is off"));
        }
        String admin = authentication != null ? authentication.getName() : "unknown";
        String reason = request.reason().trim();
        try {
            return perform(request, admin, reason);
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new StopResult(false, request.action(), List.of(),
                    e.getMessage()));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(new StopResult(false, request.action(), List.of(),
                    e.getMessage()));
        }
    }

    private ResponseEntity<StopResult> perform(StopAction request, String admin, String reason) {
        return switch (request.action().trim().toUpperCase(Locale.ROOT)) {
            case "RELEASE_DELEGATION" -> {
                if (blank(request.userId()) || blank(request.agentId())) {
                    yield ResponseEntity.badRequest().body(new StopResult(false, request.action(), List.of(),
                            "userId and agentId are required"));
                }
                stops.releaseDelegatedAgent(request.userId(), request.agentId(), admin, reason);
                yield ResponseEntity.ok(new StopResult(true, "RELEASE_DELEGATION", List.of(request.agentId()), null));
            }
            case "RELEASE_AGENT" -> {
                if (blank(request.agentId())) {
                    yield ResponseEntity.badRequest().body(new StopResult(false, request.action(), List.of(),
                            "agentId is required"));
                }
                boolean known = stops.releaseAgent(request.tenantId(), request.agentId(), admin, reason);
                yield known ? ResponseEntity.ok(new StopResult(true, "RELEASE_AGENT", List.of(request.agentId()), null))
                        : ResponseEntity.status(HttpStatus.NOT_FOUND).body(new StopResult(false, "RELEASE_AGENT",
                        List.of(), "the agent is not registered"));
            }
            case "KILL_SWITCH" -> ResponseEntity.ok(new StopResult(true, "KILL_SWITCH",
                    stops.killSwitch(request.tenantId(), request.agentType(), admin, reason), null));
            case "KILL_SWITCH_RELEASE" -> ResponseEntity.ok(new StopResult(true, "KILL_SWITCH_RELEASE",
                    stops.releaseKillSwitch(request.tenantId(), request.agentType(), admin, reason), null));
            default -> ResponseEntity.badRequest().body(new StopResult(false, request.action(), List.of(),
                    "unknown action"));
        };
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
