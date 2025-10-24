package io.contexa.contexacore.simulation.strategy;

import io.contexa.contexacore.domain.entity.AttackResult;

import java.util.Map;

/**
 * API 공격 전략 인터페이스
 *
 * API 취약점을 악용한 다양한 공격 시뮬레이션
 */
public interface IAPIAttack extends IAttackStrategy {

    /**
     * API 남용 공격 실행
     * 비즈니스 로직 취약점 악용
     */
    AttackResult executeAPIAbuse(String endpoint, Map<String, Object> maliciousParams);

    /**
     * GraphQL 주입 공격
     * GraphQL 쿼리 조작을 통한 공격
     */
    AttackResult executeGraphQLInjection(String query, int nestingDepth);

    /**
     * 속도 제한 우회 공격
     * Rate Limiting 우회 기법
     */
    AttackResult bypassRateLimit(String endpoint, int requestRate, String technique);

    /**
     * API 키 노출 공격
     * 노출된 API 키 악용
     */
    AttackResult exploitExposedAPIKey(String apiKey, String targetEndpoint);

    /**
     * CORS 정책 우회
     * Cross-Origin Resource Sharing 취약점 악용
     */
    AttackResult bypassCORS(String origin, String method);

    /**
     * API 버전 공격
     * 구 버전 API 취약점 악용
     */
    AttackResult exploitDeprecatedAPI(String version, String endpoint);

    /**
     * 매개변수 오염 공격
     * HTTP Parameter Pollution
     */
    AttackResult performParameterPollution(Map<String, String> pollutedParams);

    /**
     * API 체이닝 공격
     * 여러 API를 연쇄적으로 악용
     */
    AttackResult executeAPIChaining(String[] endpoints, Map<String, Object>[] payloads);
}