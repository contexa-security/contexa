package io.contexa.contexaidentity.security.core.mfa;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;

import java.util.Map;

/**
 * 상태별로 클라이언트에 내려줄 챌린지 정보를 생성하는 인터페이스
 */
public interface ChallengeGenerator {
    /**
     * 현재 FactorContext 상태에 맞는 챌린지 정보를 반환
     * @param ctx MFA 실행 컨텍스트
     * @return 챌린지 페이로드 (mode, url, parameters 등)
     */
    Map<String,Object> generate(FactorContext ctx);
}
