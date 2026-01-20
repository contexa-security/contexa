package io.contexa.contexacommon.enums;

import lombok.Getter;


@Getter
public enum AuditRequirement {
    
    NONE("감사 불필요", "개발 및 테스트 환경에서 감사 로깅 생략"),
    
    
    BASIC("기본 감사", "기본적인 작업 로그만 기록"),
    
    
    DETAILED("상세 감사", "모든 세부 작업과 결과를 상세히 기록"),
    
    
    COMPREHENSIVE("완전 감사", "모든 데이터, 추적 정보, 성능 메트릭 포함"),
    
    
    REQUIRED("필수 감사", "보안 요구사항에 따른 필수적인 감사 로깅");
    
    private final String displayName;
    private final String description;
    
    AuditRequirement(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }
    
    public boolean isAuditRequired() {
        return this != NONE;
    }
} 