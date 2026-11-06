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

import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationViews.DelegationBody;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationViews.DelegationView;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationViews.RevokeBody;
import io.contexa.contexaiam.admin.web.agent.service.AgentDelegationService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.util.List;
import java.util.Map;

/**
 * A person's delegations to agents (docs/agent OC-1): the signed-in person records what work an agent may do for them,
 * lists and revokes their own delegations. The person is the delegator and the writer; an agent cannot use this API.
 */
@RestController
@RequestMapping("/contexa/api/agent-delegations")
@PreAuthorize("isAuthenticated()")
public class AgentDelegationApiController {

    static final int LIST_LIMIT = 200;

    private final AgentDelegationService delegations;
    private final Clock clock;

    public AgentDelegationApiController(AgentDelegationService delegations) {
        this(delegations, Clock.systemUTC());
    }

    AgentDelegationApiController(AgentDelegationService delegations, Clock clock) {
        this.delegations = delegations;
        this.clock = clock;
    }

    @PostMapping
    public ResponseEntity<?> record(@RequestBody(required = false) DelegationBody body, Authentication authentication,
                                    HttpServletRequest request) {
        if (body == null) {
            return error(HttpStatus.BAD_REQUEST, "A delegation is required");
        }
        try {
            refuseAnAgent(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(DelegationView.of(delegations.recordOwn(
                    authentication, RequestInfoExtractor.extractTenantId(request), body.toRequest()),
                    clock.instant()));
        } catch (AgentDelegationService.AgentCallerException e) {
            return error(HttpStatus.FORBIDDEN, e.getMessage());
        } catch (IllegalArgumentException e) {
            return error(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @GetMapping
    public ResponseEntity<?> own(Authentication authentication, HttpServletRequest request) {
        try {
            refuseAnAgent(request);
            List<DelegationView> views = delegations.listOwn(authentication,
                            RequestInfoExtractor.extractTenantId(request), LIST_LIMIT).stream()
                    .map(delegation -> DelegationView.of(delegation, clock.instant())).toList();
            return ResponseEntity.ok(views);
        } catch (AgentDelegationService.AgentCallerException e) {
            return error(HttpStatus.FORBIDDEN, e.getMessage());
        }
    }

    @PostMapping("/{delegationId}/revoke")
    public ResponseEntity<?> revoke(@PathVariable("delegationId") String delegationId,
                                    @RequestBody(required = false) RevokeBody body, Authentication authentication,
                                    HttpServletRequest request) {
        try {
            refuseAnAgent(request);
            return delegations.revokeOwn(authentication, RequestInfoExtractor.extractTenantId(request), delegationId,
                            body != null ? body.reason() : null)
                    .<ResponseEntity<?>>map(delegation -> ResponseEntity.ok(DelegationView.of(delegation,
                            clock.instant())))
                    .orElseGet(() -> error(HttpStatus.NOT_FOUND, "No delegation of yours has that identifier"));
        } catch (AgentDelegationService.AgentCallerException e) {
            return error(HttpStatus.FORBIDDEN, e.getMessage());
        }
    }

    /**
     * A request the bridge stamped as an agent's is refused, as on the confirmation pages: an agent can hold a token in
     * the person's name that no claim the service reads gives away, and only the bridge reads every form of one. The
     * admin API and the console refuse it by the same reading, whatever the token's account may do.
     */
    static void refuseAnAgent(HttpServletRequest request) {
        if (fromAnAgent(request)) {
            throw new AgentDelegationService.AgentCallerException();
        }
    }

    /** Whether the bridge stamped the request as an agent's: the console refuses it by the same reading. */
    public static boolean fromAnAgent(HttpServletRequest request) {
        return request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP) instanceof DelegationStamp stamp
                && StringUtils.hasText(stamp.agentId());
    }

    static ResponseEntity<Map<String, String>> error(HttpStatus status, String message) {
        return ResponseEntity.status(status).body(Map.of("error", message));
    }
}
