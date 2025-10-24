package io.contexa.contexacommon.enums;

import lombok.Getter;

/**
 * 진단 타입 열거형
 * 
 * 각 진단 타입마다 전용 진단 전략(DiagnosisStrategy) 존재
 * 해당 전략은 적절한 Lab으로 작업을 위임
 * 타입 안전한 진단 처리 보장
 * 
 * @since 2024-01-01
 */
@Getter
public enum DiagnosisType {
    
    /**
     * 정책 생성 진단
     * - generatePolicyFromTextStream
     * - generatePolicyFromTextByAi
     */
    POLICY_GENERATION("정책 생성", "자연어 요구사항을 분석하여 IAM 정책을 생성합니다"),
    
    /**
     * 조건 템플릿 생성 진단  
     * - generateUniversalConditionTemplates
     * - generateSpecificConditionTemplates
     */
    CONDITION_TEMPLATE("조건 템플릿 생성", "범용 및 특화 조건 템플릿을 AI로 생성합니다"),
    
    /**
     * 신뢰도 평가 진단
     * - assessContext
     */
    TRUST_ASSESSMENT("신뢰도 평가", "인증 컨텍스트를 분석하여 신뢰도를 평가합니다"),
    
    /**
     * 위험 평가 진단 (신버전)
     * - AI 파이프라인 기반 위험 평가
     */
    RISK_ASSESSMENT("위험 평가", "제로 트러스트 기반 실시간 위험 평가를 수행합니다"),
    
    /**
     * 🏷️ 리소스 이름 제안 진단
     * - suggestResourceName
     * - suggestResourceNamesInBatch
     */
    RESOURCE_NAMING("리소스 이름 제안", "기술적 식별자를 사용자 친화적 이름으로 변환합니다"),
    
    /**
     * 👤 역할 추천 진단
     * - recommendRolesForUser
     */
    ROLE_RECOMMENDATION("역할 추천", "사용자에게 적합한 역할을 AI로 추천합니다"),
    
    /**
     * 보안 상태 분석 진단
     * - analyzeSecurityPosture
     */
    SECURITY_POSTURE("보안 상태 분석", "전체 시스템의 보안 상태를 분석하고 개선점을 제안합니다"),
    
    // ==================== 🏛️ AI-Native Authorization Studio 진단 타입들 ====================
    
    /**
     * Authorization Studio 자연어 질의 진단
     * - "해당 부서에서 누가 고객 데이터를 삭제할 수 있나요?"
     * - "특정 사용자가 왜 회계 시스템에 접근할 수 없죠?"
     * - "해당 팀 권한을 분석해주세요"
     */
    STUDIO_QUERY("Studio 자연어 질의", "Authorization Studio에서 자연어로 권한 구조를 질의하고 분석합니다"),
    
    /**
     * Authorization Studio 권한 이상 탐지 & 리스크 분석 진단
     * - 과도한 권한 보유자 탐지
     * - 비정상 권한 패턴 분석
     * - 권한 남용 징후 모니터링
     * - 컴플라이언스 위반 사항 점검
     */
    STUDIO_RISK_ANALYSIS("Studio 리스크 분석", "Authorization Studio에서 권한 이상을 탐지하고 보안 리스크를 분석합니다"),
    
    /**
     * 💡 Authorization Studio 스마트 권한 추천 진단
     * - 최소 권한 원칙 기반 자동 추천
     * - 역할 기반 맞춤형 권한 제안
     * - 비즈니스 컨텍스트 기반 지능형 추천
     */
    STUDIO_PERMISSION_RECOMMENDATION("Studio 권한 추천", "Authorization Studio에서 AI 기반 스마트 권한 추천을 제공합니다"),
    
    /**
     * Authorization Studio 대화형 권한 관리 진단
     * - 음성/텍스트 기반 자연어 명령 처리
     * - 대화형 권한 설정 및 수정
     * - 실시간 권한 영향 분석 및 설명
     */
    STUDIO_CONVERSATION("Studio 대화형 관리", "Authorization Studio에서 대화형 인터페이스로 권한을 관리합니다"),
    
    /**
     * Security Copilot 포괄적 보안 분석 진단
     * - 다중 Lab 협업을 통한 종합 보안 분석
     * - 권한 구조, 위험도 평가, 정책 권장사항 통합
     * - 보안 점수 계산 및 개선 방안 제시
     * - 실시간 스트리밍 분석 지원
     */
    SECURITY_COPILOT("Security Copilot", "다중 Lab 협업을 통한 포괄적 보안 분석을 수행합니다"),

    /**
     * Security Copilot 포괄적 보안 분석 진단
     * - 다중 Lab 협업을 통한 종합 보안 분석
     * - 권한 구조, 위험도 평가, 정책 권장사항 통합
     * - 보안 점수 계산 및 개선 방안 제시
     * - 실시간 스트리밍 분석 지원
     */
    BEHAVIORAL_ANALYSIS("Behavioral Analysis", "사후 대응 → 사전 예방으로 전환. 내부자 위협, 계정 탈취 등 잠재적 위험을 실시간으로 탐지하고 자동 대응하여 피해를 최소화합니다"),

    /**
     * 🏥 권한 거버넌스 분석 진단
     * - 시스템 건강 진단 의사 (System Health Doctor)
     * - 권한 배분 상태의 전반적 건강성 및 최적화 분석
     * - 비동기적/주기적 백그라운드 분석 (예: 매일 밤)
     * - 예방적 보안: 위협 발생 전 잠재적 위험 요소 탐지
     * - 권한 이상 징후 탐지 및 최적 상태 유지 지원
     */
    ACCESS_GOVERNANCE("권한 거버넌스 분석", "시스템 권한 배분 상태의 전반적 건강성과 최적화를 분석하여 예방적 보안을 구현합니다"),

    THREAT_RESPONSE("위협 응답", "위협을 감지하고 즉시 응답합니다."),

    /**
     * 🛠️ SOAR (Security Orchestration, Automation and Response) 
     * - 보안 오케스트레이션, 자동화 및 대응
     * - 대화형 인시던트 대응 및 위협 헌팅
     * - Tool Calling과 MCP 프로토콜을 통한 도구 실행
     * - Human-in-the-loop 승인 워크플로우
     * - 실시간 스트리밍 및 장기 세션 관리
     */
    SOAR("SOAR", "보안 오케스트레이션, 자동화 및 대응을 위한 대화형 AI 기반 플랫폼"),
    
    /**
     * 동적 위협 대응 (Dynamic Threat Response)
     * - 실시간 위협 탐지 및 자동 대응 정책 생성
     * - AI 기반 SpEL 표현식 자동 생성
     * - 위협 심각도 기반 동적 정책 조정
     * - 자율 진화형 정책 패브릭의 핵심 컴포넌트
     */
    DYNAMIC_THREAT_RESPONSE("동적 위협 대응", "AI 기반 실시간 위협 대응 정책을 자동으로 생성하고 적용합니다");


    private final String displayName;
    private final String description;

    DiagnosisType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    /**
     * 문자열로부터 DiagnosisType을 찾습니다
     */
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