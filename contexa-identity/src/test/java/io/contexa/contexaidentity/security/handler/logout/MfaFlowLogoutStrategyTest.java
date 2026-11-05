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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** PR-89: a sign-in waiting for its code ends with the session that logged out. */
class MfaFlowLogoutStrategyTest {

    private final MfaSessionRepository repository = mock(MfaSessionRepository.class);
    private final MfaStateMachineService stateMachines = mock(MfaStateMachineService.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
    private final MockHttpServletResponse response = new MockHttpServletResponse();

    private MfaFlowLogoutStrategy strategy() {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("repository", repository);
        beans.addBean("stateMachines", stateMachines);
        ObjectProvider<MfaSessionRepository> repositories = beans.getBeanProvider(MfaSessionRepository.class);
        ObjectProvider<MfaStateMachineService> machines = beans.getBeanProvider(MfaStateMachineService.class);
        return new MfaFlowLogoutStrategy(repositories, machines);
    }

    @Test
    @DisplayName("the flow the request names is released and removed with its cookie")
    void theFlowEndsWithTheLogout() {
        when(repository.getSessionId(request)).thenReturn("flow-1");

        strategy().execute(request, response, null);

        verify(stateMachines).releaseStateMachine("flow-1");
        verify(repository).removeSession("flow-1", request, response);
    }

    @Test
    @DisplayName("a logout needs no sign-in to end its flow: the first factor may be all the session has")
    void anAnonymousLogoutEndsItsFlowToo() {
        assertThat(strategy().supports(request, null)).isTrue();
    }

    @Test
    @DisplayName("a session without a flow changes nothing")
    void noFlowNoChange() {
        strategy().execute(request, response, null);

        verify(stateMachines, never()).releaseStateMachine(any());
        verify(repository, never()).removeSession(any(), any(), any());
    }

    @Test
    @DisplayName("a store that fails does not stop the logout")
    void aFailingStoreDoesNotStopTheLogout() {
        when(repository.getSessionId(request)).thenReturn("flow-1");
        doThrow(new IllegalStateException("store down")).when(stateMachines).releaseStateMachine("flow-1");

        assertThatCode(() -> strategy().execute(request, response, null)).doesNotThrowAnyException();
    }
}
