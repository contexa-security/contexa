package io.contexa.contexaiam.security.xacml.pdp.translator;

import java.util.Set;

/**
 * 분석된 SpEL 규칙을 트리 구조로 표현하기 위한 공통 인터페이스.
 */
public interface ExpressionNode {

    Set<String> getRequiredAuthorities();

    /**
     * 이 규칙이 주체의 인증 상태에 대한 요구사항을 포함하는지 여부.
     */
    boolean requiresAuthentication();

    String getConditionDescription();
}