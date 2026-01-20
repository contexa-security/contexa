package io.contexa.contexaiam.security.xacml.pdp.translator;


import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.expression.spel.ast.MethodReference;

@Order(Ordered.LOWEST_PRECEDENCE)
public class DefaultFunctionTranslator implements SpelFunctionTranslator {
    @Override
    public boolean supports(String functionName) {
        return true; 
    }

    @Override
    public ExpressionNode translate(String functionName, MethodReference node) {
        
        return new TerminalNode(node.toStringAST());
    }
}
