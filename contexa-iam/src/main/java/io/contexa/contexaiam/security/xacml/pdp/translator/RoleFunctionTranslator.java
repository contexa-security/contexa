package io.contexa.contexaiam.security.xacml.pdp.translator;

import org.springframework.core.annotation.Order;
import org.springframework.expression.spel.ast.MethodReference;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
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
        return new TerminalNode("역할(" + roleNames + ") 보유", authorities, true);
    }
}
