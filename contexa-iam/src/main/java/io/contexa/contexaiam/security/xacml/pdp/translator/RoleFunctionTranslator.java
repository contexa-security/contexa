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

import java.util.List;
import java.util.stream.Collectors;

@Order(20)
public class RoleFunctionTranslator implements SpelFunctionTranslator {
    @Override
    public boolean supports(String functionName) {
        return functionName.toLowerCase().contains("role");
    }

    @Override
    public ExpressionNode translate(String functionName, MethodReference node) {
        List<String> roles = extractArguments(node);
        String roleNames = String.join(", ", roles);
        String authorities = roles.stream().map(r -> "ROLE_" + r).collect(Collectors.joining(","));
        return new TerminalNode("Has role(" + roleNames + ")", authorities, true);
    }
}
