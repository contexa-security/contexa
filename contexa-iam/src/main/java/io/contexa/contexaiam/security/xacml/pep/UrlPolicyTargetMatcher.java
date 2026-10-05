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

import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.PathContainer;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * Matches URL policy targets. The URL enforcement point compiles a target into a request matcher,
 * and the policy simulator matches a path and HTTP method against the same target with the same
 * pattern parser and HTTP method rule, so both select the same policies.
 */
public final class UrlPolicyTargetMatcher {

    private static final String URL_TARGET = "URL";

    private UrlPolicyTargetMatcher() {
    }

    /**
     * Compiles a URL target into the request matcher used by the enforcement point. A target without
     * an HTTP method, or with ANY or ALL, matches every method.
     */
    public static RequestMatcher requestMatcher(PolicyTarget target) {
        return PathPatternRequestMatcher.withDefaults()
                .matcher(restrictedMethod(target.getHttpMethod()), target.getTargetIdentifier());
    }

    /**
     * Returns whether a request with the given path within the application and HTTP method matches
     * the target as its compiled request matcher would. A target that cannot be compiled matches
     * nothing.
     */
    public static boolean matches(PolicyTarget target, String path, String httpMethod) {
        if (target == null || !URL_TARGET.equals(target.getTargetType()) || path == null) {
            return false;
        }
        String identifier = target.getTargetIdentifier();
        if (identifier == null || !identifier.startsWith("/")) {
            return false;
        }
        try {
            HttpMethod method = restrictedMethod(target.getHttpMethod());
            if (method != null && !method.name().equals(httpMethod)) {
                return false;
            }
            PathPattern pattern = PathPatternParser.defaultInstance.parse(identifier);
            return pattern.matches(PathContainer.parsePath(path));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static HttpMethod restrictedMethod(String httpMethod) {
        if (httpMethod == null || "ANY".equals(httpMethod) || "ALL".equals(httpMethod)) {
            return null;
        }
        return HttpMethod.valueOf(httpMethod);
    }
}
