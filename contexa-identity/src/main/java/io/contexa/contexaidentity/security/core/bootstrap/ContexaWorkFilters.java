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
package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexacommon.store.RequestPathScope;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * The filters of one of Contexa's own chains run as Contexa's work (PR-201). What such a chain reads on the request's
 * thread is Contexa's: the client of a token request, the authorization behind a bearer token, the account and the
 * policy of a sign-in. None of it was marked, so a database that took the statement and never answered held the
 * request for as long as the caller would wait: a token request went unanswered for minutes while the database was
 * paused. Between the two filters here every read of the chain is bounded as a protected call's is; what runs behind
 * the chain, the application's handler or a console page, is not Contexa's work and keeps its own time.
 */
final class ContexaWorkFilters {

    private ContexaWorkFilters() {
    }

    /** The chain's filters, in their order, between the one that opens Contexa's work and the one that closes it. */
    static List<Filter> around(List<Filter> filters) {
        List<Filter> bounded = new ArrayList<>(filters.size() + 2);
        bounded.add(new ContexaWorkBeginFilter());
        bounded.addAll(filters);
        bounded.add(new ContexaWorkEndFilter());
        return List.copyOf(bounded);
    }

    /** First in the chain: Contexa's work starts with it and ends when the request has come back through the chain. */
    static final class ContexaWorkBeginFilter implements Filter {

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            RequestPathScope.enter();
            try {
                chain.doFilter(request, response);
            } finally {
                RequestPathScope.leave();
            }
        }
    }

    /** Last in the chain: what it hands the request to is the application's, until the request comes back. */
    static final class ContexaWorkEndFilter implements Filter {

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            int work = RequestPathScope.suspend();
            try {
                chain.doFilter(request, response);
            } finally {
                RequestPathScope.resume(work);
            }
        }
    }
}
