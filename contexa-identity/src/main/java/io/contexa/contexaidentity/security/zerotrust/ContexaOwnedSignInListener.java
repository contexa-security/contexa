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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A single-factor sign-in of Contexa's own login (CONTEXA_OWNED) whose flow keeps Spring Security's own filter and
 * success handler: a form, a one-time code or a passkey on the session state. Such a filter publishes the interactive
 * sign-in, and this listener sends it to the engine as {@link HostOwnedSignInListener} sends the application's own.
 * The filters of an MFA flow's factors publish the same event at each factor; that is no sign-in yet, and the flow's
 * final success sends the completed one ({@code AbstractMfaAuthenticationSuccessHandler}). A request signs in once,
 * whichever reports it first.
 */
@Slf4j
public class ContexaOwnedSignInListener implements ApplicationListener<InteractiveAuthenticationSuccessEvent> {

    private final ZeroTrustEventPublisher publisher;
    private final MfaStateMachineIntegrator mfaFlows;

    public ContexaOwnedSignInListener(ZeroTrustEventPublisher publisher, MfaStateMachineIntegrator mfaFlows) {
        this.publisher = publisher;
        this.mfaFlows = mfaFlows;
    }

    @Override
    public void onApplicationEvent(InteractiveAuthenticationSuccessEvent event) {
        HttpServletRequest request = RequestContextHolder.getRequestAttributes() instanceof
                ServletRequestAttributes attributes ? attributes.getRequest() : null;
        Authentication authentication = event.getAuthentication();
        if (request != null && factorOfAnMfaFlow(request, authentication)) {
            return;
        }
        Map<String, Object> signIn = new HashMap<>();
        signIn.put("authenticationType", SignInDecision.SINGLE);
        signIn.put("signedInBy", event.getGeneratedBy().getSimpleName());
        SignInDecision.send(publisher, authentication, request, signIn);
    }

    /**
     * Whether the request is a step of the person's MFA flow. A flow that cannot be read hides no sign-in: it is sent,
     * and a final success of the same request would find it sent.
     */
    private boolean factorOfAnMfaFlow(HttpServletRequest request, Authentication authentication) {
        try {
            FactorContext flow = mfaFlows != null ? mfaFlows.loadFactorContextFromRequest(request) : null;
            return flow != null && authentication != null
                    && Objects.equals(flow.getUsername(), authentication.getName());
        } catch (RuntimeException e) {
            log.error("[Contexa] The MFA flow of a sign-in could not be read; the sign-in is sent: {}", e.getMessage());
            return false;
        }
    }
}
