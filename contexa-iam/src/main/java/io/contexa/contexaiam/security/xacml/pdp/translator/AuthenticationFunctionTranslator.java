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
            case "isauthenticated" -> new TerminalNode("인증된 사용자", true);
            case "isfullyauthenticated" -> new TerminalNode("완전 인증 사용자(Remember-Me 아님)", true);
            case "isanonymous" -> new TerminalNode("익명 사용자", false);
            case "isrememberme" -> new TerminalNode("Remember-Me 인증 사용자", true);
            default -> new TerminalNode(node.toStringAST());
        };
    }
}