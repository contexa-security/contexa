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
package io.contexa.contexaidentity.security.service.ott;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FlowBoundOneTimeTokenRequestResolverTest {

    private static final String THIEF = "thief";
    private static final String VICTIM = "victim";

    private static FactorContext flowOf(String user, String flow) {
        return new FactorContext(UUID.randomUUID().toString(),
                UsernamePasswordAuthenticationToken.authenticated(user, null, List.of()), MfaState.NONE, flow);
    }

    private static MockHttpServletRequest codeRequest(String username) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/mfa/ott/generate-code");
        if (username != null) {
            request.setParameter("username", username);
        }
        return request;
    }

    @Test
    @DisplayName("a flow of one's own does not ask for a code in another user's name")
    void aFlowAsksForItsOwnUserOnly() {
        FlowBoundOneTimeTokenRequestResolver resolver =
                new FlowBoundOneTimeTokenRequestResolver(request -> flowOf(THIEF, "mfa"));

        assertThatThrownBy(() -> resolver.resolve(codeRequest(VICTIM)))
                .isInstanceOf(OneTimeTokenAddressRefusedException.class);
    }

    @Test
    @DisplayName("a flow asks for the code of its own user")
    void aFlowAsksForItsUser() {
        FlowBoundOneTimeTokenRequestResolver resolver =
                new FlowBoundOneTimeTokenRequestResolver(request -> flowOf(VICTIM, "mfa"));

        assertThat(resolver.resolve(codeRequest(VICTIM)).getUsername()).isEqualTo(VICTIM);
    }

    @Test
    @DisplayName("the address a flow's user named goes on to be checked against the account")
    void theAddressGoesOn() {
        FlowBoundOneTimeTokenRequestResolver resolver =
                new FlowBoundOneTimeTokenRequestResolver(request -> flowOf(VICTIM, "mfa"));
        MockHttpServletRequest request = codeRequest(VICTIM);
        request.setParameter("email", "victim@example.test");

        GenerateOneTimeTokenRequest resolved = resolver.resolve(request);

        assertThat(resolved).isInstanceOf(EmailGenerateOneTimeTokenRequest.class);
        assertThat(((EmailGenerateOneTimeTokenRequest) resolved).getEmail()).isEqualTo("victim@example.test");
    }

    @Test
    @DisplayName("before a sign-in there is no flow, and the name is the form's")
    void withoutAFlowTheNameIsTheForms() {
        FlowBoundOneTimeTokenRequestResolver resolver = new FlowBoundOneTimeTokenRequestResolver(request -> null);

        assertThat(resolver.resolve(codeRequest(VICTIM)).getUsername()).isEqualTo(VICTIM);
    }

    @Test
    @DisplayName("a context of another kind of sign-in binds nothing")
    void anotherKindOfFlowBindsNothing() {
        FlowBoundOneTimeTokenRequestResolver resolver =
                new FlowBoundOneTimeTokenRequestResolver(request -> flowOf(THIEF, "ott"));

        assertThat(resolver.resolve(codeRequest(VICTIM)).getUsername()).isEqualTo(VICTIM);
    }

    @Test
    @DisplayName("a request that names nobody asks for nothing")
    void noNameNoRequest() {
        FlowBoundOneTimeTokenRequestResolver resolver =
                new FlowBoundOneTimeTokenRequestResolver(request -> flowOf(THIEF, "mfa"));

        assertThat(resolver.resolve(codeRequest(null))).isNull();
        assertThat(resolver.resolve(codeRequest(" "))).isNull();
    }
}
