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

import lombok.Getter;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
public class LogicalNode implements ExpressionNode {

    private final String operator;
    private final List<ExpressionNode> children;

    public LogicalNode(String operator, List<ExpressionNode> children) {
        this.operator = operator;
        this.children = children;
    }

    @Override
    public Set<String> getRequiredAuthorities() {
        return children.stream()
                .flatMap(node -> node.getRequiredAuthorities().stream())
                .collect(Collectors.toSet());
    }

    @Override
    public boolean requiresAuthentication() {
        return children.stream().anyMatch(ExpressionNode::requiresAuthentication);
    }

    @Override
    public String getConditionDescription() {
        if ("NOT".equals(operator)) {
            return "NOT (" + children.get(0).getConditionDescription() + ")";
        }
        return "(" + children.stream()
                .map(ExpressionNode::getConditionDescription)
                .collect(Collectors.joining(" " + operator + " ")) + ")";
    }
}
