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

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.util.Map;

/**
 * The failure handler one step of one flow is given: the counterpart of {@link StepScopedSuccessHandler}. The
 * application's failureHandler option and the failure address of the step are handed to the shared handler for the
 * request of that step only.
 */
public final class StepScopedFailureHandler implements PlatformAuthenticationFailureHandler {

    static final String ATTRIBUTE = StepScopedFailureHandler.class.getName() + ".settings";

    /** What the step of the current request set: its own handler of the application and its failure address. */
    record Settings(@Nullable PlatformAuthenticationFailureHandler delegate, @Nullable String failureUrl) {
    }

    private final PlatformAuthenticationFailureHandler shared;
    @Nullable
    private final PlatformAuthenticationFailureHandler delegate;
    private volatile String failureUrl;

    private StepScopedFailureHandler(PlatformAuthenticationFailureHandler shared,
                                     @Nullable PlatformAuthenticationFailureHandler delegate) {
        this.shared = shared;
        this.delegate = delegate;
    }

    /**
     * The handler to give the step: the shared handler behind a step scope when it is one of Contexa's shared
     * handlers, otherwise the handler as it is.
     */
    @Nullable
    public static PlatformAuthenticationFailureHandler of(@Nullable PlatformAuthenticationFailureHandler shared,
                                                          @Nullable PlatformAuthenticationFailureHandler delegate) {
        if (shared instanceof AbstractTokenBasedFailureHandler || shared instanceof SessionBasedFailureHandler) {
            return new StepScopedFailureHandler(shared, delegate);
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
        this.failureUrl = defaultTargetUrl;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        inScope(request, () -> shared.onAuthenticationFailure(request, response, exception));
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception, @Nullable FactorContext factorContext,
                                        FailureType failureType, Map<String, Object> errorDetails)
            throws IOException, ServletException {
        inScope(request, () -> shared.onAuthenticationFailure(request, response, exception, factorContext,
                failureType, errorDetails));
    }

    private void inScope(HttpServletRequest request, Answer answer) throws IOException, ServletException {
        Object previous = request.getAttribute(ATTRIBUTE);
        request.setAttribute(ATTRIBUTE, new Settings(delegate, failureUrl));
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
