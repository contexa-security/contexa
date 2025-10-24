package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.core.Ordered;

/**
 * 인증 플랫폼 전체 설정/흐름 구성용 인터페이스
 */
public interface SecurityConfigurer extends Ordered {
    /**
     * 플랫폼 전역 초기화 (Global) 단계에서 호출
     */
    void init(PlatformContext ctx, PlatformConfig config);

    /**
     * Flow별 configure 단계에서 호출
     */
    void configure(FlowContext fc) throws Exception;

    /**
     * getOrder() 로 실행 우선순위 결정.
     *   낮을수록 먼저 실행(즉, 내부(default) 설정 → 큰 값을 가진 사용자(Dsl) 설정 순)
     */
    @Override
    default int getOrder() {
        return 500;  // 기본값: 가장 나중에 실행
    }
}

