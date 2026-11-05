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
package io.contexa.contexaiam.security.xacml.pep;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Q-11 (PR-59): a suppressed model call names the session by its reference, as the decision observations do. */
class ProtectableLlmSuppressionWriterSessionTest {

    @AfterEach
    void releaseRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void aSuppressionKeepsNoLiveSessionId() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setSession(new MockHttpSession(null, "LIVE-SESSION-1"));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        JdbcOperations jdbc = mock(JdbcOperations.class);
        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(Object.class.getMethod("toString"));

        new ProtectableLlmSuppressionWriter(() -> jdbc, new ObjectMapper(), null)
                .recordSuppressed(new TestingAuthenticationToken("alice", "n/a"), invocation, "REASON", "ENFORCE");

        ArgumentCaptor<Object[]> arguments = ArgumentCaptor.forClass(Object[].class);
        verify(jdbc).update(anyString(), arguments.capture());
        assertThat(Arrays.asList(arguments.getValue()))
                .contains(RequestFactRedaction.sessionReference("LIVE-SESSION-1"))
                .doesNotContain("LIVE-SESSION-1");
    }
}
