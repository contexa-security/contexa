package io.contexa.contexaiam.security.xacml.pdp.translator;


import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.expression.spel.ast.MethodReference;
import org.springframework.stereotype.Component;

@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class DefaultFunctionTranslator implements SpelFunctionTranslator {
    @Override
    public boolean supports(String functionName) {
        return true; // 항상 지원 (폴백)
    }

    @Override
    public ExpressionNode translate(String functionName, MethodReference node) {
        // 번역할 수 없는 경우, SpEL 표현식 원본을 그대로 반환
        return new TerminalNode(node.toStringAST());
    }
}
