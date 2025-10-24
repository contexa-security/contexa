package io.contexa.contexaiam.security.xacml.pdp.translator;

import lombok.Getter;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 'AND', 'OR', 'NOT'과 같은 논리적 조합을 표현하는 복합 노드 (Composite).
 */
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

    /**
     * [추가] 자식 노드 중 하나라도 인증을 요구하면 true를 반환.
     */
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
