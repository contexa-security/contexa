package io.contexa.contexaiam.aiam.service;

import io.contexa.contexaiam.common.event.dto.DomainEvent;

/**
 * 도메인 이벤트를 구독하여 플랫폼의 모든 데이터를 AI가 이해할 수 있는 벡터 형태로
 * Vector DB에 지속적으로 공급하는 데이터 인제스천 서비스.
 */
public interface DataIngestionService {

    /**
     * 도메인 이벤트를 받아 해당 이벤트를 벡터화하고 저장소에 인덱싱합니다.
     * 이 메서드는 @Async로 실행되어야 합니다.
     * @param event 사용자 생성/수정, 정책 변경 등 모든 도메인 이벤트
     */
    void ingestEvent(DomainEvent event);

    /**
     * 시스템 초기화 시 모든 기존 데이터를 벡터화하여 저장소에 채웁니다.
     */
    void initialIndexing();
}