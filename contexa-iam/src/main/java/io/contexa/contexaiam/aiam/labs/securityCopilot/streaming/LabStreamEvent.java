package io.contexa.contexaiam.aiam.labs.securityCopilot.streaming;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

/**
 * Lab 스트리밍 이벤트 모델
 * 각 Lab의 스트림 메시지를 캡슐화
 */
@Getter
@Builder
public class LabStreamEvent {
    private final String labName;           // Lab 이름 (예: "StudioQuery")
    private final String labDisplayName;    // 표시 이름 (예: "권한분석")
    private final String content;           // 실제 메시지 내용
    private final int priority;             // 우선순위 (1이 가장 높음)
    private final long sequence;            // 전체 시퀀스 번호
    private final LocalDateTime timestamp;  // 생성 시간
    private final EventType eventType;      // 이벤트 타입
    private final boolean isComplete;       // Lab 완료 여부

    public enum EventType {
        START,      // Lab 시작
        PROGRESS,   // 진행 중
        RESULT,     // 중간 결과
        COMPLETE,   // Lab 완료
        ERROR       // 오류 발생
    }

    /**
     * 포맷팅된 메시지 생성
     */
    public String getFormattedMessage() {
        if (eventType == EventType.START) {
            return String.format("\n\n=== [%s] 분석 시작 ===\n", labDisplayName);
        } else if (eventType == EventType.COMPLETE) {
            return String.format("\n[%s 분석 완료]\n\n", labDisplayName);
        } else if (eventType == EventType.ERROR) {
            return String.format("\n[%s] %s\n", labDisplayName, content);
        } else {
            // PROGRESS 타입은 내용만 반환 (태그 없이)
            return content;
        }
    }

    /**
     * 우선순위 기반 정렬을 위한 가중치 계산
     */
    public long getSortWeight() {
        // priority * 1000000 + sequence
        // 이렇게 하면 우선순위가 높은 Lab이 먼저 처리됨
        return (long) priority * 1000000L + sequence;
    }
}