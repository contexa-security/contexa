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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import java.time.Instant;
import io.contexa.contexacommon.domain.EventTimeZone;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.context.collector.DefaultRoleScopeCollector;
import io.contexa.contexacore.autonomous.context.collector.RoleScopeCollector;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;

/**
 * Keeps a real authorization denial of a protected method as a fact without analysing it: a line in the session
 * record and a denied observation of the user's authorization scope, so that later decisions see what the user was
 * refused and the role scope learns its forbidden families.
 */
@Slf4j
public class AuthorizationDenialRecorder {

    private final ZeroTrustEventPublisher zeroTrustEventPublisher;
    private final SecurityContextDataStore dataStore;
    private final RoleScopeCollector roleScopeCollector;
    private final ContextObservationRecorder recorder;

    /** A recorder that commits through the role scope collector's own recorder, where the collector stages. */
    public AuthorizationDenialRecorder(ZeroTrustEventPublisher zeroTrustEventPublisher,
                                       SecurityContextDataStore dataStore,
                                       @Nullable RoleScopeCollector roleScopeCollector) {
        this(zeroTrustEventPublisher, dataStore, roleScopeCollector,
                roleScopeCollector instanceof DefaultRoleScopeCollector collector ? collector.recorder()
                        : new ContextObservationRecorder(dataStore));
    }

    public AuthorizationDenialRecorder(ZeroTrustEventPublisher zeroTrustEventPublisher,
                                       SecurityContextDataStore dataStore,
                                       @Nullable RoleScopeCollector roleScopeCollector,
                                       ContextObservationRecorder recorder) {
        this.zeroTrustEventPublisher = zeroTrustEventPublisher;
        this.dataStore = dataStore;
        this.roleScopeCollector = roleScopeCollector;
        this.recorder = recorder;
    }

    /** A protected method's policy refused the call. */
    public void record(MethodInvocation methodInvocation, Authentication authentication, @Nullable String reason) {
        try {
            keep(zeroTrustEventPublisher.buildMethodAuthorizationEvent(
                    methodInvocation, authentication, false, reason,
                    ZeroTrustEventPublisher.METHOD_NOT_RUN, null));
        } catch (RuntimeException e) {
            log.error("Failed to record an authorization denial: method={}",
                    methodInvocation.getMethod().getName(), e);
        }
    }

    /** A URL authorization policy refused the current request of an authenticated user. */
    public void recordRequest(Authentication authentication, @Nullable String reason) {
        try {
            keep(zeroTrustEventPublisher.buildRequestAuthorizationEvent(authentication, false, reason));
        } catch (RuntimeException e) {
            log.error("Failed to record a URL authorization denial: user={}",
                    authentication != null ? authentication.getName() : null, e);
        }
    }

    private void keep(ZeroTrustSpringEvent event) {
        SecurityEvent securityEvent = ZeroTrustSecurityEventConverter.convert(event);
        recordSessionLine(securityEvent);
        if (roleScopeCollector != null) {
            roleScopeCollector.collect(securityEvent);
        }
        // The refusal is the request's final outcome: its session decision and denied scope are recorded once (W2-7).
        recorder.commit(securityEvent, SessionDecisionRecord.AUTHORIZATION_DENIED, true);
    }

    private void recordSessionLine(SecurityEvent event) {
        String sessionId = event.getSessionId();
        if (!StringUtils.hasText(sessionId)) {
            return;
        }
        LocalDateTime time = event.getLocalTimestamp() != null ? event.getLocalTimestamp() : EventTimeZone.toLocal(Instant.now());
        Object method = event.getMetadata() != null ? event.getMetadata().get("httpMethod") : null;
        Object path = event.getMetadata() != null ? event.getMetadata().get("requestPath") : null;
        dataStore.addSessionAction(sessionId, String.format("%02d:%02d | AUTHORIZATION_DENIED | %s %s | %s",
                time.getHour(), time.getMinute(),
                method != null ? method : "-",
                path != null ? path : "-",
                event.getSourceIp() != null ? event.getSourceIp() : "-"));
    }
}
