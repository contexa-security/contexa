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
package io.contexa.contexaiam.security.xacml.pdp.evaluation.url;

import org.springframework.core.annotation.Order;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

@Order(0)
public class AuthenticatedExpressionEvaluator implements ExpressionEvaluator {
    @Override
    public boolean supports(String expression) {
        return "isAuthenticated()".equals(expression) || "isFullyAuthenticated()".equals(expression);
    }

    @Override
    public AuthorizationManager<RequestAuthorizationContext> createManager(String expression) {
        if ("isAuthenticated()".equals(expression)) {
            return AuthenticatedAuthorizationManager.authenticated();
        }
        return AuthenticatedAuthorizationManager.fullyAuthenticated();
    }
}