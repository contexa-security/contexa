package io.contexa.contexacore.std.labs;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * 범용 AI Lab 인터페이스
 *
 * 모든 AI 연구소(Lab)가 구현해야 하는 통합 API
 * 각 Lab의 처리 로직을 표준화하여 Strategy에서 일관된 방식으로 호출 가능
 *
 * @param <Req> 요청(Query) 타입
 * @param <Res> 응답(Response) 타입
 */
public interface AILab<Req, Res> {

    /**
     * Lab의 고유 ID 반환
     * 기존 AbstractIAMLab.getLabId()와 동일
     */
    String getLabId();

    /**
     * Lab의 이름 반환
     * 기존 AbstractIAMLab.getLabName()과 동일
     */
    String getLabName();

    /**
     * 동기적으로 요청을 처리
     *
     * @param request 처리할 요청
     * @return 처리 결과
     */
    Res process(Req request);

    /**
     * 비동기로 요청을 처리
     *
     * @param request 처리할 요청
     * @return 처리 결과 (Mono)
     */
    Mono<Res> processAsync(Req request);

    /**
     * 스트리밍 방식으로 요청을 처리
     *
     * @param request 처리할 요청
     * @return 스트리밍 결과
     */
    Flux<String> processStream(Req request);

    /**
     * 스트리밍 지원 여부
     *
     * @return 스트리밍 지원 여부
     */
    default boolean supportsStreaming() {
        return false;
    }

    /**
     * Lab의 상태 확인
     *
     * @return 활성 상태 여부
     */
    default boolean isActive() {
        return true;
    }

    /**
     * Lab의 처리 가능 여부 확인
     *
     * @param request 확인할 요청
     * @return 처리 가능 여부
     */
    default boolean canProcess(Req request) {
        return request != null && isActive();
    }
}