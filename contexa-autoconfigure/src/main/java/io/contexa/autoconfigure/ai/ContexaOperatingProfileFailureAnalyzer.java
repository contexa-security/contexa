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
package io.contexa.autoconfigure.ai;

import io.contexa.autoconfigure.core.infra.ContexaPlatformActivation;
import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.operating.ContexaOperatingProfileException;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.diagnostics.FailureAnalyzer;
import org.springframework.core.env.Environment;
import org.springframework.lang.Nullable;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.UnreachableFilterChainException;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A refused start says why and what to change, instead of a stack trace.
 * <p>
 * With mode FULL Contexa's main chain takes every request the chains before it leave. Spring Security refuses an application
 * chain that takes every request ahead of it ({@link UnreachableFilterChainException}, finding F-2) while it builds its filter,
 * before Contexa's own start-up check could name that chain. That refusal is told in the words of the check (R-14 of
 * docs/agent/운영모드-정상화-구현계획.md, {@link OwnershipStartupDiagnostics#applicationChainsRefused}): the application's
 * chain by its bean name, and what to change. Where Contexa does not run in mode FULL Spring Security's own words stand.
 */
class ContexaOperatingProfileFailureAnalyzer implements FailureAnalyzer {

    /** How Spring Security writes the bean name of a chain, which it gives nowhere else ({@link DefaultSecurityFilterChain#toString()}). */
    private static final Pattern BEAN_NAME = Pattern.compile("defined as '([^']+)'");

    @Nullable
    private final Environment environment;

    /**
     * @param environment the environment of the application that failed to start; Spring Boot gives none to a failure that
     *                    came before the application context existed
     */
    ContexaOperatingProfileFailureAnalyzer(@Nullable Environment environment) {
        this.environment = environment;
    }

    @Override
    @Nullable
    public FailureAnalysis analyze(Throwable failure) {
        ContexaOperatingProfileException refused = cause(failure, ContexaOperatingProfileException.class);
        if (refused != null) {
            return new FailureAnalysis(refused.getMessage(), refused.action(), refused);
        }
        UnreachableFilterChainException unreachable = cause(failure, UnreachableFilterChainException.class);
        if (unreachable == null || !runsInFullMode()) {
            return null;
        }
        String chain = applicationChainForEveryRequest(unreachable.getFilterChain());
        if (chain == null) {
            return null;
        }
        ContexaOperatingProfileException refusal = OwnershipStartupDiagnostics.applicationChainsRefused(List.of(chain));
        return new FailureAnalysis(refusal.getMessage(), refusal.action(), unreachable);
    }

    /** Contexa is switched on in this application, and in mode FULL. */
    private boolean runsInFullMode() {
        return environment != null && ContexaPlatformActivation.isActive(environment)
                && ContexaOperatingProfile.resolve(environment).mode() == SecurityMode.FULL;
    }

    /**
     * The chain Spring Security found taking every request ahead of another, by its bean name, or by its request matcher when
     * it is no bean; {@code null} when it is not such a chain. With mode FULL every chain of Contexa's is narrowed or no
     * {@link DefaultSecurityFilterChain}, so a chain that takes every request is the application's.
     */
    @Nullable
    static String applicationChainForEveryRequest(@Nullable SecurityFilterChain chain) {
        if (!(chain instanceof DefaultSecurityFilterChain everyRequest)
                || !(everyRequest.getRequestMatcher() instanceof AnyRequestMatcher)) {
            return null;
        }
        Matcher name = BEAN_NAME.matcher(everyRequest.toString());
        return name.find() ? name.group(1) : everyRequest.getRequestMatcher().toString();
    }

    @Nullable
    private static <T extends Throwable> T cause(Throwable failure, Class<T> type) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (type.isInstance(cause)) {
                return type.cast(cause);
            }
        }
        return null;
    }
}
