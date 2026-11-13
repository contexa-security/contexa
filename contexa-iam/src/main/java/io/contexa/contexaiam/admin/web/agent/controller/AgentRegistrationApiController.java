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

import io.contexa.contexaiam.common.ErrorBody;
import io.contexa.contexacore.autonomous.agent.AgentRegistration;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexaiam.admin.web.agent.dto.AgentView;
import io.contexa.contexaiam.admin.web.agent.service.AgentProvisioning;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.Supplier;

/**
 * The admin API of agent registration (docs/agent OC-3): register an agent with its OAuth2 client (and its account),
 * rotate the client's secret, transfer the sponsor, deregister and remove. The agent is named in the body, since agent
 * identifiers may hold any character. A secret is returned once and never again.
 */
@RestController
@RequestMapping("/contexa/admin/api/agents")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AgentRegistrationApiController {

    /** An agent to register. {@code tokenLifetimeMinutes} is optional. */
    public record RegisterBody(String tenantId, String agentId, String displayName, String agentType, String sponsorId,
                               String clientId, List<String> scopes, Boolean ownToken, Boolean actsForPeople,
                               Long tokenLifetimeMinutes, Boolean account, List<String> accountGroups) {

        AgentProvisioning.Registration toRegistration() {
            return new AgentProvisioning.Registration(tenantId, agentId, displayName, agentType, sponsorId, clientId,
                    scopes, ownToken, actsForPeople,
                    AgentProvisioning.tokenLifetimeOfMinutes(tokenLifetimeMinutes), account,
                    accountGroups);
        }
    }

    /** An agent to act on, with the new sponsor or the reason when the action takes one. */
    public record AgentBody(String tenantId, String agentId, String sponsorId, String reason) {
    }

    /** The registration and the secrets shown once. */
    public record CredentialsView(AgentView agent, String clientId, String clientSecret, String accountUsername,
                                  String accountPassword) {

        static CredentialsView of(AgentProvisioning.Credentials credentials) {
            return new CredentialsView(AgentView.of(credentials.registration()), credentials.clientId(),
                    credentials.clientSecret(), credentials.accountUsername(), credentials.accountPassword());
        }
    }

    private final AgentProvisioning provisioning;
    private final AgentRegistry registry;

    public AgentRegistrationApiController(AgentProvisioning provisioning, AgentRegistry registry) {
        this.provisioning = provisioning;
        this.registry = registry;
    }

    @GetMapping
    public List<AgentView> list(@RequestParam(value = "tenantId", required = false) String tenantId,
                                @RequestParam(value = "limit", defaultValue = "500") int limit) {
        return registry.list(tenantId == null || tenantId.isBlank() ? null : tenantId.trim(),
                Math.max(1, Math.min(limit, AgentAdminController.LIST_LIMIT))).stream().map(AgentView::of).toList();
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody(required = false) RegisterBody body, Authentication authentication) {
        if (body == null) {
            return error(HttpStatus.BAD_REQUEST, "A registration is required");
        }
        return act(() -> ResponseEntity.status(HttpStatus.CREATED).body(CredentialsView.of(
                provisioning.register(body.toRegistration(), authentication.getName()))));
    }

    @PostMapping("/secret")
    public ResponseEntity<?> rotateSecret(@RequestBody(required = false) AgentBody body, Authentication authentication) {
        return body == null ? error(HttpStatus.BAD_REQUEST, "An agent is required")
                : act(() -> ResponseEntity.ok(CredentialsView.of(provisioning.rotateSecret(body.tenantId(),
                body.agentId(), authentication.getName()))));
    }

    @PostMapping("/sponsor")
    public ResponseEntity<?> transferSponsor(@RequestBody(required = false) AgentBody body,
                                             Authentication authentication) {
        return body == null ? error(HttpStatus.BAD_REQUEST, "An agent is required")
                : act(() -> ResponseEntity.ok(view(provisioning.transferSponsor(body.tenantId(), body.agentId(),
                body.sponsorId(), authentication.getName()))));
    }

    @PostMapping("/deregister")
    public ResponseEntity<?> deregister(@RequestBody(required = false) AgentBody body, Authentication authentication) {
        return body == null ? error(HttpStatus.BAD_REQUEST, "An agent is required")
                : act(() -> ResponseEntity.ok(view(provisioning.deregister(body.tenantId(), body.agentId(),
                body.reason(), authentication.getName()))));
    }

    @PostMapping("/remove")
    public ResponseEntity<?> remove(@RequestBody(required = false) AgentBody body, Authentication authentication) {
        return body == null ? error(HttpStatus.BAD_REQUEST, "An agent is required")
                : act(() -> ResponseEntity.ok(view(provisioning.remove(body.tenantId(), body.agentId(),
                authentication.getName()))));
    }

    private ResponseEntity<?> act(Supplier<ResponseEntity<?>> action) {
        if (!provisioning.available()) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "Contexa's OAuth2 authorization server is not running");
        }
        try {
            return action.get();
        } catch (NoSuchElementException e) {
            return error(HttpStatus.NOT_FOUND, e.getMessage());
        } catch (IllegalArgumentException e) {
            return error(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    private static AgentView view(AgentRegistration registration) {
        return AgentView.of(registration);
    }

    private static ResponseEntity<ErrorBody> error(HttpStatus status, String message) {
        return ResponseEntity.status(status).body(new ErrorBody(message));
    }
}
