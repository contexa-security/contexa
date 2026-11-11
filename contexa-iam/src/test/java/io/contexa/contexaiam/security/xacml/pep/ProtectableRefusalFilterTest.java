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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.AuthorizationDeniedException;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The refusal of a protected method that reached the servlet filters, on a path no Spring Security chain covers: it is
 * answered as Spring Security's exception translation answers it, and nothing else is.
 */
class ProtectableRefusalFilterTest {

    private final ProtectableRefusalFilter filter = new ProtectableRefusalFilter();
    private final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/h/m/secured");
    private final MockHttpServletResponse response = new MockHttpServletResponse();

    private static FilterChain throwing(Exception failure) {
        return (request, response) -> {
            if (failure instanceof ServletException servletFailure) {
                throw servletFailure;
            }
            if (failure instanceof IOException ioFailure) {
                throw ioFailure;
            }
            throw (RuntimeException) failure;
        };
    }

    /** As the DispatcherServlet hands on what a handler threw. */
    private static ServletException dispatched(RuntimeException failure) {
        return new ServletException("Request processing failed: " + failure, failure);
    }

    @Test
    void aCallWithoutAUserTheInterceptorRefusedIsAnswered401() throws Exception {
        AuthenticationCredentialsNotFoundException refusal = ProtectableRefusalFilter.markRefusal(request,
                new AuthenticationCredentialsNotFoundException("no user"));

        filter.doFilter(request, response, throwing(dispatched(refusal)));

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.isCommitted()).isTrue();
    }

    @Test
    void aCallTheMethodPoliciesRefusedIsAnswered403() throws Exception {
        AuthorizationDeniedException refusal = ProtectableRefusalFilter.markRefusal(request,
                new AuthorizationDeniedException("Access is denied by method policies"));

        filter.doFilter(request, response, throwing(dispatched(refusal)));

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void theRefusalAsItLeftTheInterceptorIsAnsweredToo() throws Exception {
        AuthenticationCredentialsNotFoundException refusal = ProtectableRefusalFilter.markRefusal(request,
                new AuthenticationCredentialsNotFoundException("no user"));

        filter.doFilter(request, response, throwing(refusal));

        assertThat(response.getStatus()).isEqualTo(401);
    }

    /** Spring Security's translation looks into the causes as well. */
    @Test
    void aRefusalTheApplicationWrappedIsFoundInside() throws Exception {
        AuthenticationCredentialsNotFoundException refusal = ProtectableRefusalFilter.markRefusal(request,
                new AuthenticationCredentialsNotFoundException("no user"));

        filter.doFilter(request, response, throwing(dispatched(new IllegalStateException("the application's", refusal))));

        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void anExceptionOfTheSameTypeThatIsTheApplicationsStaysItsOwn() {
        ProtectableRefusalFilter.markRefusal(request, new AuthenticationCredentialsNotFoundException("no user"));
        ServletException theApplications = dispatched(new AuthenticationCredentialsNotFoundException("the application's"));

        assertThatThrownBy(() -> filter.doFilter(request, response, throwing(theApplications))).isSameAs(theApplications);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.isCommitted()).isFalse();
    }

    @Test
    void withoutARefusalOfTheInterceptorEveryExceptionStays() {
        ServletException failure = dispatched(new AuthenticationCredentialsNotFoundException("no user"));

        assertThatThrownBy(() -> filter.doFilter(request, response, throwing(failure))).isSameAs(failure);

        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void aResponseAlreadyCommittedIsNotTouched() {
        AuthenticationCredentialsNotFoundException refusal = ProtectableRefusalFilter.markRefusal(request,
                new AuthenticationCredentialsNotFoundException("no user"));
        response.setCommitted(true);
        ServletException failure = dispatched(refusal);

        assertThatThrownBy(() -> filter.doFilter(request, response, throwing(failure))).isSameAs(failure);

        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void anIoFailureStaysAsItIs() {
        ProtectableRefusalFilter.markRefusal(request, new AuthenticationCredentialsNotFoundException("no user"));
        IOException failure = new IOException("the client went away");

        assertThatThrownBy(() -> filter.doFilter(request, response, throwing(failure))).isSameAs(failure);
    }

    @Test
    void aRequestThatFailsNothingIsNotTouched() throws Exception {
        filter.doFilter(request, response, (req, res) -> res.getWriter().write("fine"));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentAsString()).isEqualTo("fine");
    }

    @Test
    void aRefusalOffARequestIsHandedBackUnmarked() {
        AuthenticationCredentialsNotFoundException refusal = new AuthenticationCredentialsNotFoundException("no user");

        assertThat(ProtectableRefusalFilter.markRefusal(null, refusal)).isSameAs(refusal);
    }
}
