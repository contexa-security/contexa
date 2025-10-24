package io.contexa.contexaiam.security.xacml.pdp.translator;

import org.springframework.expression.spel.SpelNode;
import org.springframework.expression.spel.ast.CompoundExpression;
import org.springframework.expression.spel.ast.MethodReference;
import org.springframework.expression.spel.ast.StringLiteral;

import java.util.ArrayList;
import java.util.List;

/**
 * SpEL의 특정 함수(MethodReference)를 분석하여 ExpressionNode로 번역하는 전략 인터페이스
 */
public interface SpelFunctionTranslator {

    /**
     * 이 번역기가 주어진 함수 이름을 지원하는지 확인합니다.
     * @param functionName SpEL 함수 이름 (예: "hasRole")
     * @return 지원 여부
     */
    boolean supports(String functionName);

    /**
     * 지원하는 함수를 ExpressionNode로 번역합니다.
     * @param functionName SpEL 함수 이름
     * @param node 분석할 MethodReference AST 노드
     * @return 번역된 ExpressionNode
     */
    ExpressionNode translate(String functionName, MethodReference node);

    /**
     * 메서드 호출 노드에서 문자열 인자들을 추출하는 유틸리티 메서드.
     * @param node 메서드 참조 노드
     * @return 추출된 문자열 인자 리스트
     */
    default List<String> extractArguments(MethodReference node) {
        List<String> args = new ArrayList<>();
        for (int i = 0; i < node.getChildCount(); i++) {
            SpelNode child = node.getChild(i);
            // 'hasAuthority("AUTH")' 와 같은 단일 인자 처리
            if (child instanceof StringLiteral) {
                args.add(((StringLiteral) child).getLiteralValue().getValue().toString());
            }
            // 'hasAnyAuthority("A", "B")' 와 같은 복합 인자 처리
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