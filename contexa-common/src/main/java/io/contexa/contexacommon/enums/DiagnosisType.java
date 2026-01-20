package io.contexa.contexacommon.enums;

import lombok.Getter;


@Getter
public enum DiagnosisType {
    
    
    POLICY_GENERATION("정책 생성", "자연어 요구사항을 분석하여 IAM 정책을 생성합니다"),
    
    
    CONDITION_TEMPLATE("조건 템플릿 생성", "범용 및 특화 조건 템플릿을 AI로 생성합니다"),
    
    
    TRUST_ASSESSMENT("신뢰도 평가", "인증 컨텍스트를 분석하여 신뢰도를 평가합니다"),
    
    
    RISK_ASSESSMENT("위험 평가", "제로 트러스트 기반 실시간 위험 평가를 수행합니다"),
    
    
    RESOURCE_NAMING("리소스 이름 제안", "기술적 식별자를 사용자 친화적 이름으로 변환합니다"),
    
    
    ROLE_RECOMMENDATION("역할 추천", "사용자에게 적합한 역할을 AI로 추천합니다"),
    
    
    SECURITY_POSTURE("보안 상태 분석", "전체 시스템의 보안 상태를 분석하고 개선점을 제안합니다"),
    
    
    
    
    STUDIO_QUERY("Studio 자연어 질의", "Authorization Studio에서 자연어로 권한 구조를 질의하고 분석합니다"),
    
    
    STUDIO_RISK_ANALYSIS("Studio 리스크 분석", "Authorization Studio에서 권한 이상을 탐지하고 보안 리스크를 분석합니다"),
    
    
    STUDIO_PERMISSION_RECOMMENDATION("Studio 권한 추천", "Authorization Studio에서 AI 기반 스마트 권한 추천을 제공합니다"),
    
    
    STUDIO_CONVERSATION("Studio 대화형 관리", "Authorization Studio에서 대화형 인터페이스로 권한을 관리합니다"),
    
    
    SECURITY_COPILOT("Security Copilot", "다중 Lab 협업을 통한 포괄적 보안 분석을 수행합니다"),

    
    BEHAVIORAL_ANALYSIS("Behavioral Analysis", "사후 대응 → 사전 예방으로 전환. 내부자 위협, 계정 탈취 등 잠재적 위험을 실시간으로 탐지하고 자동 대응하여 피해를 최소화합니다"),

    
    ACCESS_GOVERNANCE("권한 거버넌스 분석", "시스템 권한 배분 상태의 전반적 건강성과 최적화를 분석하여 예방적 보안을 구현합니다"),

    THREAT_RESPONSE("위협 응답", "위협을 감지하고 즉시 응답합니다."),

    
    SOAR("SOAR", "보안 오케스트레이션, 자동화 및 대응을 위한 대화형 AI 기반 플랫폼"),
    
    
    DYNAMIC_THREAT_RESPONSE("동적 위협 대응", "AI 기반 실시간 위협 대응 정책을 자동으로 생성하고 적용합니다");


    private final String displayName;
    private final String description;

    DiagnosisType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    
    public static DiagnosisType fromString(String type) {
        for (DiagnosisType diagnosisType : values()) {
            if (diagnosisType.name().equalsIgnoreCase(type) ||
                diagnosisType.displayName.equalsIgnoreCase(type)) {
                return diagnosisType;
            }
        }
        throw new IllegalArgumentException("Unknown diagnosis type: " + type);
    }
} 