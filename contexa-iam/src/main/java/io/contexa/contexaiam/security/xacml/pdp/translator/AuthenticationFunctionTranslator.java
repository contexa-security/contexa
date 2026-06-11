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
package io.contexa.contexaiam.security.xacml.pdp.translator;

import org.springframework.core.annotation.Order;
import org.springframework.expression.spel.ast.MethodReference;

@Order(10)
public class AuthenticationFunctionTranslator implements SpelFunctionTranslator {
    @Override
    public boolean supports(String functionName) {
        return switch (functionName.toLowerCase()) {
            case "isauthenticated", "isfullyauthenticated", "isanonymous", "isrememberme" -> true;
            default -> false;
        };
    }

    @Override
    public ExpressionNode translate(String functionName, MethodReference node) {
        return switch (functionName.toLowerCase()) {
            case "isauthenticated" -> new TerminalNode("Authenticated user", true);
            case "isfullyauthenticated" -> new TerminalNode("Fully authenticated user (not Remember-Me)", true);
            case "isanonymous" -> new TerminalNode("Anonymous user", false);
            case "isrememberme" -> new TerminalNode("Remember-Me authenticated user", true);
            default -> new TerminalNode(node.toStringAST());
        };
    }
}