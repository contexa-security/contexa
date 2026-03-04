package io.contexa.contexaiam.security.xacml.pdp.translator;

import org.springframework.core.annotation.Order;
import org.springframework.expression.spel.ast.MethodReference;

import java.util.List;

@Order(30)
public class AuthorityFunctionTranslator implements SpelFunctionTranslator {
    @Override
    public boolean supports(String functionName) {
        return functionName.toLowerCase().contains("authority");
    }

    @Override
    public ExpressionNode translate(String functionName, MethodReference node) {
        List<String> authorities = extractArguments(node);
        String authorityNames = String.join(", ", authorities);
        return new TerminalNode("Has authority(" + authorityNames + ")", authorityNames, true);
    }
}
