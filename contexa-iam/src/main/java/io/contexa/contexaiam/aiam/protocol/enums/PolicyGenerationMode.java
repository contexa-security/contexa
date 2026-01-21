package io.contexa.contexaiam.aiam.protocol.enums;

public enum PolicyGenerationMode {
    
    QUICK("빠른 생성", "기본 템플릿을 활용한 신속한 정책 생성"),

    AI_ASSISTED("AI 지원 생성", "AI가 적극적으로 지원하는 정책 생성 모드"),

    PRECISE("정밀 생성", "완전한 AI 분석을 통한 정밀한 정책 생성"),

    EXPERIMENTAL("실험적 생성", "최신 AI 기법을 적용한 실험적 정책 생성");
    
    private final String displayName;
    private final String description;
    
    PolicyGenerationMode(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }
} 