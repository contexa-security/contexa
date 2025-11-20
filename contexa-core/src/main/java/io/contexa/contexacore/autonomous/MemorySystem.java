package io.contexa.contexacore.autonomous;

import reactor.core.publisher.Mono;
import java.util.Map;

/**
 * MemorySystem - 메모리 시스템 인터페이스
 *
 * <p>
 * Enterprise 모듈에서 WM(Working Memory) 및 STM(Short-Term Memory) 기능을 제공하는 인터페이스입니다.
 * Spring Boot AutoConfiguration을 통해 자동으로 주입됩니다.
 * </p>
 *
 * @since 0.1.0-ALPHA
 */
public interface MemorySystem {

    /**
     * Working Memory에 저장
     *
     * @param key 메모리 키
     * @param value 저장할 값
     * @param namespace 네임스페이스
     * @return 저장 결과 Mono
     */
    Mono<Void> storeInWM(String key, Object value, String namespace);

    /**
     * Short-Term Memory에 저장
     *
     * @param key 메모리 키
     * @param value 저장할 값
     * @param metadata 메타데이터
     * @return 저장 결과 Mono
     */
    Mono<Void> storeInSTM(String key, Object value, Map<String, Object> metadata);
}
