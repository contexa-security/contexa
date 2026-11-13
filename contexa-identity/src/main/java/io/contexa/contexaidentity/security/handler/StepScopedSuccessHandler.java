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
package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.io.IOException;

/**
 * The success handler one step of one flow is given. Contexa's success handlers are shared beans; what a step sets on
 * them (the application's successHandler option, the default success address) is kept here instead and handed to the
 * shared handler for the request of that step only. Kept on the shared bean, the step configured last decided for
 * every flow and every step.
 */
public final class StepScopedSuccessHandler implements PlatformAuthenticationSuccessHandler {

    static final String ATTRIBUTE = StepScopedSuccessHandler.class.getName() + ".settings";

    /** What the step of the current request set: its own handler of the application and its default address. */
    record Settings(@Nullable PlatformAuthenticationSuccessHandler delegate, @Nullable String defaultTargetUrl,
                    boolean alwaysUse) {
    }

    private final PlatformAuthenticationSuccessHandler shared;
    @Nullable
    private final PlatformAuthenticationSuccessHandler delegate;
    private volatile String defaultTargetUrl;
    private volatile boolean alwaysUse;

    private StepScopedSuccessHandler(PlatformAuthenticationSuccessHandler shared,
                                     @Nullable PlatformAuthenticationSuccessHandler delegate) {
        this.shared = shared;
        this.delegate = delegate;
    }

    /**
     * The handler to give the step: the shared handler behind a step scope when it is one of Contexa's shared
     * handlers, otherwise the handler as it is.
     */
    @Nullable
    public static PlatformAuthenticationSuccessHandler of(@Nullable PlatformAuthenticationSuccessHandler shared,
                                                          @Nullable PlatformAuthenticationSuccessHandler delegate) {
        if (shared instanceof AbstractTokenBasedSuccessHandler || shared instanceof SessionBasedSuccessHandler) {
            return new StepScopedSuccessHandler(shared, delegate);
        }
        return shared;
    }

    /** The settings of the step whose request is being answered, or {@code null} outside a step's request. */
    @Nullable
    static Settings current(HttpServletRequest request) {
        return request.getAttribute(ATTRIBUTE) instanceof Settings settings ? settings : null;
    }

    @Override
    public void setDefaultTargetUrl(String defaultTargetUrl) {
        this.defaultTargetUrl = defaultTargetUrl;
    }

    @Override
    public void setAlwaysUse(boolean alwaysUse) {
        this.alwaysUse = alwaysUse;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        inScope(request, () -> shared.onAuthenticationSuccess(request, response, authentication));
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication, TokenTransportResult result)
            throws IOException, ServletException {
        inScope(request, () -> shared.onAuthenticationSuccess(request, response, authentication, result));
    }

    private void inScope(HttpServletRequest request, Answer answer) throws IOException, ServletException {
        Object previous = request.getAttribute(ATTRIBUTE);
        request.setAttribute(ATTRIBUTE, new Settings(delegate, defaultTargetUrl, alwaysUse));
        try {
            answer.run();
        } finally {
            if (previous == null) {
                request.removeAttribute(ATTRIBUTE);
            } else {
                request.setAttribute(ATTRIBUTE, previous);
            }
        }
    }

    @FunctionalInterface
    private interface Answer {
        void run() throws IOException, ServletException;
    }
}
