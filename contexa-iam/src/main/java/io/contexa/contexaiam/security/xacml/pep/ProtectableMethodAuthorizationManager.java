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

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;

import java.util.function.Supplier;

@Slf4j
@RequiredArgsConstructor
public class ProtectableMethodAuthorizationManager {

    private final MethodSecurityExpressionHandler expressionHandler;

    public void protectable(Supplier<Authentication> authentication, MethodInvocation mi) {

        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, mi);

        Object protectableRuleObj = ctx.lookupVariable("protectableRule");
        if (protectableRuleObj instanceof Expression protectableRule) {
            boolean result = ExpressionUtils.evaluateAsBoolean(protectableRule, ctx);
            if (!result) {
                throw new AuthorizationDeniedException("Access is denied");
            }
        } else {
            log.warn("[ZeroTrust] preAuthorize - preAuthorizeRule variable is missing or not of Expression type: {}",
                    protectableRuleObj != null ? protectableRuleObj.getClass().getSimpleName() : "null");
            throw new AuthorizationDeniedException("Access is denied - preAuthorizeRule not found");
        }
    }
}