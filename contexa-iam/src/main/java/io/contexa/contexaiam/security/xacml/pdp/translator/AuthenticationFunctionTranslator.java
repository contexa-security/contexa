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