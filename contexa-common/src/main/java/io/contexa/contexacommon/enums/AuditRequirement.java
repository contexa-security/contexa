package io.contexa.contexacommon.enums;

import lombok.Getter;

/**
 * IAM 작업의 감사 요구사항을 정의하는 열거형
 * AI 작업시 적용될 감사 로깅의 수준을 결정합니다
 */
@Getter
public enum AuditRequirement {
    /**
     * 감사 불필요 - 개발/테스트용
     */
    NONE("감사 불필요", "개발 및 테스트 환경에서 감사 로깅 생략"),
    
    /**
     * 기본 감사 - 기본적인 로깅
     */
    BASIC("기본 감사", "기본적인 작업 로그만 기록"),
    
    /**
     * 상세 감사 - 모든 세부사항 기록
     */
    DETAILED("상세 감사", "모든 세부 작업과 결과를 상세히 기록"),
    
    /**
     * 완전 감사 - 모든 데이터와 추적 정보 포함
     */
    COMPREHENSIVE("완전 감사", "모든 데이터, 추적 정보, 성능 메트릭 포함"),
    
    /**
     * 필수 감사 - 보안 요구사항에 따른 필수 감사
     */
    REQUIRED("필수 감사", "보안 요구사항에 따른 필수적인 감사 로깅");
    
    private final String displayName;
    private final String description;
    
    AuditRequirement(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }
    /**
     * 감사가 필요한지 확인합니다
     * @return 감사 필요 여부
     */
    public boolean isAuditRequired() {
        return this != NONE;
    }
} 