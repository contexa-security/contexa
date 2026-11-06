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
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.handler.OAuth2SingleAuthSuccessHandler;
import io.contexa.contexaidentity.security.handler.SessionSingleAuthSuccessHandler;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.zerotrust.ContexaOwnedSignInListener;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** Where Contexa owns the sign-in, every way its login completes reaches the engine's sign-in decision. */
class SignInDecisionWiringTest {

    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);

    private ObjectProvider<ZeroTrustEventPublisher> thePublisher() {
        DefaultListableBeanFactory factory = new DefaultListableBeanFactory();
        factory.registerSingleton("contexaZeroTrustEventPublisher", publisher);
        return factory.getBeanProvider(ZeroTrustEventPublisher.class);
    }

    @Test
    void theSingleFactorHandlersSendTheSignIn() {
        IdentityHandlerAutoConfiguration configuration = new IdentityHandlerAutoConfiguration();

        SessionSingleAuthSuccessHandler session = configuration.sessionSingleAuthSuccessHandler(
                mock(AuthResponseWriter.class), new AuthContextProperties(), null, thePublisher());
        OAuth2SingleAuthSuccessHandler token = configuration.oauth2SingleAuthSuccessHandler(mock(TokenService.class),
                mock(AuthResponseWriter.class), new AuthContextProperties(), null, thePublisher());

        assertThat(ReflectionTestUtils.getField(session, "zeroTrustEventPublisher")).isSameAs(publisher);
        assertThat(ReflectionTestUtils.getField(token, "zeroTrustEventPublisher")).isSameAs(publisher);
    }

    @Test
    void theSignInOfSpringSecuritysOwnFiltersIsHeard() {
        ContexaOwnedSignInListener listener = new IdentitySecurityCoreContexaOwnedConfiguration()
                .contexaOwnedSignInListener(publisher, mock(MfaStateMachineIntegrator.class));

        assertThat(ReflectionTestUtils.getField(listener, "publisher")).isSameAs(publisher);
    }
}
