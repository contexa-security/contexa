package io.contexa.contexaiam.aiam.protocol.enums;

/**
 * 정책 생성 모드를 정의하는 열거형
 * AI가 정책을 생성할 때 적용할 전략을 결정합니다
 */
public enum PolicyGenerationMode {
    /**
     * 빠른 생성 - 기본 템플릿 기반
     */
    QUICK("빠른 생성", "기본 템플릿을 활용한 신속한 정책 생성"),
    
    /**
     * AI 지원 생성 - AI가 지원하는 정책 생성
     */
    AI_ASSISTED("AI 지원 생성", "AI가 적극적으로 지원하는 정책 생성 모드"),
    
    /**
     * 정밀 생성 - 완전한 AI 분석 기반
     */
    PRECISE("정밀 생성", "완전한 AI 분석을 통한 정밀한 정책 생성"),
    
    /**
     * 실험적 생성 - 최신 AI 기법 적용
     */
    EXPERIMENTAL("실험적 생성", "최신 AI 기법을 적용한 실험적 정책 생성");
    
    private final String displayName;
    private final String description;
    
    PolicyGenerationMode(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }
    
    /**
     * 정책 생성 모드의 표시명을 반환합니다
     * @return 한국어 표시명
     */
    public String getDisplayName() {
        return displayName;
    }
    
    /**
     * 정책 생성 모드의 상세 설명을 반환합니다
     * @return 상세 설명
     */
    public String getDescription() {
        return description;
    }
} 