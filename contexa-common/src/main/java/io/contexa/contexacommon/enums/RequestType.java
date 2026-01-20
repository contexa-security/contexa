package io.contexa.contexacommon.enums;

import lombok.Getter;


@Getter
public enum RequestType {
    QUERY("조회", "데이터 조회 요청"),
    COMMAND("명령", "시스템 상태 변경 요청"),
    ANALYSIS("분석", "데이터 분석 요청"),
    GENERATION("생성", "콘텐츠 생성 요청"),
    VALIDATION("검증", "데이터 검증 요청"),
    OPTIMIZATION("최적화", "성능 최적화 요청"),
    MONITORING("모니터링", "시스템 모니터링 요청"),
    THREAT_RESPONSE("위협 대응", "AI 기반 위협 대응 계획 생성 및 실행 요청");
    
    private final String displayName;
    private final String description;
    
    RequestType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }
}