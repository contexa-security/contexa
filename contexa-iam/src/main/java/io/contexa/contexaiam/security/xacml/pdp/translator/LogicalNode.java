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
            return "NOT (" + children.getFirst().getConditionDescription() + ")";
        }
        return "(" + children.stream()
                .map(ExpressionNode::getConditionDescription)
                .collect(Collectors.joining(" " + operator + " ")) + ")";
    }
}
