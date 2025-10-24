package io.contexa.contexaidentity.security.core.mfa.context;

import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.enums.AuthType;

import java.util.List;
import java.util.Set;

/**
 * FactorContext 확장 인터페이스
 */
public interface FactorContextExtensions {

    /**
     * 재시도 횟수 가져오기
     */
    int getRetryCount();

    /**
     * 사용 가능한 팩터 목록 가져오기
     */
    Set<AuthType> getAvailableFactors();

    /**
     * 완료된 팩터 목록 가져오기
     */
    List<AuthenticationStepConfig> getCompletedFactors();

    /**
     * 마지막 에러 메시지 가져오기
     */
    String getLastError();

    /**
     * 생성 시간 가져오기 (타임스탬프)
     */
    long getCreatedAt();
}