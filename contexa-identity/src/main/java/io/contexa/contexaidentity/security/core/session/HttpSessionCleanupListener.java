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
package io.contexa.contexaidentity.security.core.session;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.security.zerotrust.AbstractZeroTrustSecurityService;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionIdListener;
import jakarta.servlet.http.HttpSessionListener;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;

/**
 * Releases the in-memory state tied to an HTTP session when the servlet container destroys the session or replaces
 * its id: the session's Zero Trust tracking and an MFA flow the user never finished. Both are reachable only through
 * that session, so nothing that is still in use is released.
 */
@Slf4j
public class HttpSessionCleanupListener implements HttpSessionListener, HttpSessionIdListener {

    private final ObjectProvider<ZeroTrustSecurityService> zeroTrustSecurityService;
    private final ObjectProvider<MfaSessionRepository> mfaSessionRepository;
    private final ObjectProvider<MfaStateMachineService> mfaStateMachineService;

    public HttpSessionCleanupListener(
            ObjectProvider<ZeroTrustSecurityService> zeroTrustSecurityService,
            ObjectProvider<MfaSessionRepository> mfaSessionRepository,
            ObjectProvider<MfaStateMachineService> mfaStateMachineService) {
        this.zeroTrustSecurityService = zeroTrustSecurityService;
        this.mfaSessionRepository = mfaSessionRepository;
        this.mfaStateMachineService = mfaStateMachineService;
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        HttpSession session = event.getSession();
        forgetZeroTrustSession(session.getId());
        MfaSessionRepository repository = mfaSessionRepository.getIfAvailable();
        String mfaSessionId = repository == null ? null : repository.sessionIdOf(session);
        if (mfaSessionId == null) {
            return;
        }
        try {
            MfaStateMachineService stateMachines = mfaStateMachineService.getIfAvailable();
            if (stateMachines != null) {
                stateMachines.releaseStateMachine(mfaSessionId);
            }
            repository.forgetSession(mfaSessionId);
        } catch (RuntimeException e) {
            log.error("[HttpSessionCleanup] Failed to release the MFA flow of a destroyed session", e);
        }
    }

    @Override
    public void sessionIdChanged(HttpSessionEvent event, String oldSessionId) {
        forgetZeroTrustSession(oldSessionId);
    }

    private void forgetZeroTrustSession(String sessionId) {
        if (zeroTrustSecurityService.getIfAvailable() instanceof AbstractZeroTrustSecurityService service) {
            try {
                service.forgetSession(sessionId);
            } catch (RuntimeException e) {
                log.error("[HttpSessionCleanup] Failed to forget a destroyed session", e);
            }
        }
    }
}
