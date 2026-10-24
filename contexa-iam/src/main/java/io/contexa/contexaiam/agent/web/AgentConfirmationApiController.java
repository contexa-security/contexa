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
package io.contexa.contexaiam.agent.web;

import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.agent.AgentConfirmation;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationService;
import io.contexa.contexacore.autonomous.agent.AgentRequestBinding;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Locale;

/**
 * Where an agent follows the confirmation of its request (docs/agent A5-2): it polls the confirmation the gate
 * answered with, and it may ask for one itself for a request a policy lets through only once confirmed. Only the
 * agent the confirmation is about reads it.
 */
@RestController
@RequestMapping("/contexa/api/agent-confirmations")
@PreAuthorize("isAuthenticated()")
public class AgentConfirmationApiController {

    /** A confirmation as its agent reads it; a refused one ({@code refused}) is not asked again. */
    public record ConfirmationStatus(String confirmationId, String status, boolean refused, String expiresAt,
                                     @Nullable String decidedAt, @Nullable String authorizationId, String method,
                                     String target, String trigger) {

        static ConfirmationStatus of(AgentConfirmation confirmation) {
            return new ConfirmationStatus(confirmation.confirmationId(), confirmation.status().name(),
                    confirmation.status().refused(), confirmation.expiresAt().toString(),
                    confirmation.decidedAt() != null ? confirmation.decidedAt().toString() : null,
                    confirmation.status() == AgentConfirmation.Status.APPROVED
                            || confirmation.status() == AgentConfirmation.Status.USED
                            ? confirmation.authorizationId() : null,
                    confirmation.method(), confirmation.target(), confirmation.trigger());
        }
    }

    /**
     * The request the agent asks a confirmation for: its method, its path with the query, and its body's SHA-256 in
     * hexadecimal (none for no body), as it will send it.
     */
    public record ConfirmationAsk(String method, String target, @Nullable String bodySha256, @Nullable String reason) {
    }

    private final AgentConfirmationService confirmations;

    public AgentConfirmationApiController(AgentConfirmationService confirmations) {
        this.confirmations = confirmations;
    }

    @GetMapping("/{id}")
    public ResponseEntity<ConfirmationStatus> status(@PathVariable("id") String id, Authentication authentication,
                                                     HttpServletRequest request) {
        ZeroTrustSubject subject = agent(authentication, request);
        if (subject == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return confirmations.status(id)
                .filter(confirmation -> confirmation.subjectKey().equals(subject.storageKey()))
                .map(confirmation -> ResponseEntity.ok(ConfirmationStatus.of(confirmation)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<ConfirmationStatus> ask(@RequestBody(required = false) ConfirmationAsk ask,
                                                  Authentication authentication, HttpServletRequest request) {
        ZeroTrustSubject subject = agent(authentication, request);
        if (subject == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        if (ask == null || !StringUtils.hasText(ask.method()) || !StringUtils.hasText(ask.target())
                || !ask.target().startsWith("/")) {
            return ResponseEntity.badRequest().build();
        }
        String target = ask.target().trim();
        int query = target.indexOf('?');
        String path = query < 0 ? target : target.substring(0, query);
        String hash = AgentRequestBinding.hash(subject.tenantId(), subject.userId(), subject.agentId(), ask.method(),
                path, query < 0 ? null : target.substring(query + 1),
                StringUtils.hasText(ask.bodySha256()) ? ask.bodySha256().trim().toLowerCase(Locale.ROOT) : null, null);
        return confirmations.request(new AgentConfirmationService.ConfirmationRequest(subject, hash,
                        ask.method().trim().toUpperCase(Locale.ROOT), target, AgentConfirmation.REQUESTED,
                        StringUtils.hasText(ask.reason()) ? truncate(ask.reason().trim(), 1000) : null,
                        null, null))
                .map(confirmation -> ResponseEntity.status(HttpStatus.ACCEPTED).body(ConfirmationStatus.of(confirmation)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.CONFLICT).build());
    }

    private static String truncate(String value, int length) {
        return value.length() > length ? value.substring(0, length) : value;
    }

    /** The agent the request is from, or null for a person's request. */
    @Nullable
    private static ZeroTrustSubject agent(Authentication authentication, HttpServletRequest request) {
        if (authentication == null || !(request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP)
                instanceof DelegationStamp stamp) || !StringUtils.hasText(stamp.agentId())) {
            return null;
        }
        // The gate binds the request with the same tenant (RequestInfoExtractor), so the hashes meet.
        ZeroTrustSubject subject = ZeroTrustSubject.of(authentication.getName(), stamp,
                RequestInfoExtractor.extractTenantId(request));
        return subject != null && subject.agentId() != null ? subject : null;
    }
}
