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
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.regex.Pattern;

@Order(1)
public class AuthorityExpressionEvaluator implements ExpressionEvaluator {
    private static final Pattern AUTHORITY_PATTERN = Pattern.compile("^[A-Z_]+$");

    @Override
    public boolean supports(String expression) {
        return AUTHORITY_PATTERN.matcher(expression).matches();
    }

    @Override
    public AuthorizationManager<RequestAuthorizationContext> createManager(String expression) {
        return AuthorityAuthorizationManager.hasAuthority(expression);
    }
}