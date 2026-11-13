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
import io.contexa.contexacore.autonomous.agent.AgentCallGuard;
import io.contexa.contexacore.autonomous.agent.AgentConfirmation;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationService;
import io.contexa.contexacore.autonomous.agent.AgentRequestBinding;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
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
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

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
