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

import io.contexa.contexacommon.security.bridge.OAuth2AuthenticationSupport;
import io.contexa.contexacore.autonomous.event.support.HostSignInEvents;
import io.contexa.contexacore.autonomous.store.LoginFailureRecording;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;

import java.util.function.Supplier;

/**
 * The application's failed sign-ins (HOST_OWNED). Contexa takes no part in them: it hears the events of the application's
 * authentication manager and keeps a failure for the decisions on that name to read, and for nothing else. The lock of
 * an account and the limit of an address never see it. The application's authentication is only read.
 * <p>
 * A manager that publishes no events leaves the count unknown, which {@link HostSignInEvents} tells apart from zero.
 */
@Slf4j
public class HostOwnedSignInFailureListener implements ApplicationListener<AbstractAuthenticationEvent> {

    private final Supplier<SecurityContextDataStore> store;
    private final HostSignInEvents signInEvents;

    public HostOwnedSignInFailureListener(Supplier<SecurityContextDataStore> store, HostSignInEvents signInEvents) {
        this.store = store;
        this.signInEvents = signInEvents;
    }

    @Override
    public void onApplicationEvent(AbstractAuthenticationEvent event) {
        try {
            boolean failure = event instanceof AbstractAuthenticationFailureEvent;
            if (!failure && !(event instanceof AuthenticationSuccessEvent)
                    || OAuth2AuthenticationSupport.isTokenTraffic(event.getAuthentication())) {
                return;
            }
            signInEvents.reached();
            if (failure && judgedTheCredentials(event)) {
                LoginFailureRecording.recordOnce(store.get(), event.getAuthentication().getName(), null);
            }
        } catch (RuntimeException e) {
            log.error("[Contexa] The application's sign-in could not be noted for the decisions: {}", e.getMessage(), e);
        }
    }

    /** A manager with no provider or a store that did not answer says nothing of the person who tried. */
    private static boolean judgedTheCredentials(AbstractAuthenticationEvent event) {
        return !(event instanceof AuthenticationFailureServiceExceptionEvent)
                && !(event instanceof AuthenticationFailureProviderNotFoundEvent);
    }
}
