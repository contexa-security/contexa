package io.contexa.contexaiam.security.xacml.pdp.translator;

import org.springframework.expression.spel.SpelNode;
import org.springframework.expression.spel.ast.CompoundExpression;
import org.springframework.expression.spel.ast.MethodReference;
import org.springframework.expression.spel.ast.StringLiteral;

import java.util.ArrayList;
import java.util.List;

public interface SpelFunctionTranslator {

    boolean supports(String functionName);

    ExpressionNode translate(String functionName, MethodReference node);

    default List<String> extractArguments(MethodReference node) {
        List<String> args = new ArrayList<>();
        for (int i = 0; i < node.getChildCount(); i++) {
            SpelNode child = node.getChild(i);
            
            if (child instanceof StringLiteral) {
                args.add(((StringLiteral) child).getLiteralValue().getValue().toString());
            }
            
            else if (child instanceof CompoundExpression) {
                for (int j = 0; j < child.getChildCount(); j++) {
                    if (child.getChild(j) instanceof StringLiteral) {
                        args.add(((StringLiteral) child.getChild(j)).getLiteralValue().getValue().toString());
                    }
                }
            }
        }
        return args;
    }
}