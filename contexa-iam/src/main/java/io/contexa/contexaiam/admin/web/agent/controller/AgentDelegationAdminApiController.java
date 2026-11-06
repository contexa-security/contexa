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

import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationViews.DelegationBody;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationViews.DelegationView;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationViews.RevokeBody;
import io.contexa.contexaiam.admin.web.agent.service.AgentDelegationService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.util.List;

/**
 * The admin API of delegations (docs/agent OC-1): administrators and the application's integrations list delegations,
 * record them for people as the application's own records state them (who wrote each and when), and revoke them with
 * a reason. Every change is audited. An agent is refused here as on the person's API, whatever account its token is
 * in: a delegation is a person's word, and an administrator's token does not make an agent's request a person's.
 */
@RestController
@RequestMapping("/contexa/admin/api/agent-delegations")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AgentDelegationAdminApiController {

    private final AgentDelegationService delegations;
    private final Clock clock;

    public AgentDelegationAdminApiController(AgentDelegationService delegations) {
        this(delegations, Clock.systemUTC());
    }

    AgentDelegationAdminApiController(AgentDelegationService delegations, Clock clock) {
        this.delegations = delegations;
        this.clock = clock;
    }

    @GetMapping
    public ResponseEntity<?> list(@RequestParam(value = "tenantId", required = false) String tenantId,
                                  @RequestParam(value = "delegatorId", required = false) String delegatorId,
                                  @RequestParam(value = "agentId", required = false) String agentId,
                                  @RequestParam(value = "limit", defaultValue = "200") int limit,
                                  HttpServletRequest request) {
        try {
            AgentDelegationApiController.refuseAnAgent(request);
        } catch (AgentDelegationService.AgentCallerException e) {
            return AgentDelegationApiController.error(HttpStatus.FORBIDDEN, e.getMessage());
        }
        int bounded = Math.max(1, Math.min(limit, AgentDelegationApiController.LIST_LIMIT));
        List<DelegationView> views = delegations.list(blank(tenantId), blank(delegatorId), blank(agentId), bounded)
                .stream().map(delegation -> DelegationView.of(delegation, clock.instant())).toList();
        return ResponseEntity.ok(views);
    }

    @PostMapping
    public ResponseEntity<?> record(@RequestBody(required = false) DelegationBody body, Authentication authentication,
                                    HttpServletRequest request) {
        if (body == null) {
            return AgentDelegationApiController.error(HttpStatus.BAD_REQUEST, "A delegation is required");
        }
        try {
            AgentDelegationApiController.refuseAnAgent(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(DelegationView.of(
                    delegations.recordFor(authentication.getName(), body.toRequest()), clock.instant()));
        } catch (AgentDelegationService.AgentCallerException e) {
            return AgentDelegationApiController.error(HttpStatus.FORBIDDEN, e.getMessage());
        } catch (IllegalArgumentException e) {
            return AgentDelegationApiController.error(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/{delegationId}/revoke")
    public ResponseEntity<?> revoke(@PathVariable("delegationId") String delegationId,
                                    @RequestBody(required = false) RevokeBody body, Authentication authentication,
                                    HttpServletRequest request) {
        try {
            AgentDelegationApiController.refuseAnAgent(request);
            return delegations.revokeAsAdministrator(authentication.getName(), delegationId,
                            body != null ? body.reason() : null)
                    .<ResponseEntity<?>>map(delegation -> ResponseEntity.ok(DelegationView.of(delegation,
                            clock.instant())))
                    .orElseGet(() -> AgentDelegationApiController.error(HttpStatus.NOT_FOUND,
                            "No delegation has that identifier"));
        } catch (AgentDelegationService.AgentCallerException e) {
            return AgentDelegationApiController.error(HttpStatus.FORBIDDEN, e.getMessage());
        } catch (IllegalArgumentException e) {
            return AgentDelegationApiController.error(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    private static String blank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
