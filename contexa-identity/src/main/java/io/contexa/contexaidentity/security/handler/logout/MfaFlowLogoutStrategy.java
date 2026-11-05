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
package io.contexa.contexaidentity.security.handler.logout;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.core.Authentication;

/**
 * Ends the MFA flow of the session that logs out (PR-89). A flow kept in a shared store outlives the HTTP session
 * unless it is ended here, and whoever held its cookie could finish a sign-in the user had left. The HTTP session
 * cleanup listener does the same when a session ends without a logout. Runs first: the request still names the flow.
 */
@Slf4j
public class MfaFlowLogoutStrategy implements LogoutStrategy {

    private final ObjectProvider<MfaSessionRepository> sessionRepository;
    private final ObjectProvider<MfaStateMachineService> stateMachineService;

    public MfaFlowLogoutStrategy(ObjectProvider<MfaSessionRepository> sessionRepository,
                                 ObjectProvider<MfaStateMachineService> stateMachineService) {
        this.sessionRepository = sessionRepository;
        this.stateMachineService = stateMachineService;
    }

    @Override
    public boolean supports(HttpServletRequest request, Authentication authentication) {
        return sessionRepository.getIfAvailable() != null;
    }

    @Override
    public void execute(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        MfaSessionRepository repository = sessionRepository.getIfAvailable();
        if (repository == null) {
            return;
        }
        try {
            String mfaSessionId = repository.getSessionId(request);
            if (mfaSessionId == null) {
                return;
            }
            MfaStateMachineService stateMachines = stateMachineService.getIfAvailable();
            if (stateMachines != null) {
                stateMachines.releaseStateMachine(mfaSessionId);
            }
            repository.removeSession(mfaSessionId, request, response);
        } catch (RuntimeException e) {
            log.error("[Logout] Failed to end the MFA flow of the session that logs out", e);
        }
    }
}
