package io.contexa.contexacore.soar;

import io.contexa.contexacore.domain.SoarRequest;
import reactor.core.publisher.Mono;

/**
 * SoarLab - SOAR 분석 및 대응 실행 인터페이스
 *
 * <p>
 * Enterprise 모듈에서 SOAR Lab 기능을 제공하는 인터페이스입니다.
 * Spring Boot AutoConfiguration을 통해 자동으로 주입됩니다.
 * </p>
 *
 * @since 0.1.0-ALPHA
 */
public interface SoarLab {

    /**
     * SOAR 비동기 분석 및 대응 실행
     *
     * @param request SOAR 요청 객체
     * @return 분석 결과 Mono
     */
    Mono<?> processAsync(SoarRequest request);
}
