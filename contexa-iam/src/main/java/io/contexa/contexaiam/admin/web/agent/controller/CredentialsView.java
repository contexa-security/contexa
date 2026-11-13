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

/** The registration and the secrets shown once. */
public record CredentialsView(AgentView agent, String clientId, String clientSecret, String accountUsername,
                              String accountPassword) {

    static CredentialsView of(AgentProvisioning.Credentials credentials) {
        return new CredentialsView(AgentView.of(credentials.registration()), credentials.clientId(),
                credentials.clientSecret(), credentials.accountUsername(), credentials.accountPassword());
    }
}
