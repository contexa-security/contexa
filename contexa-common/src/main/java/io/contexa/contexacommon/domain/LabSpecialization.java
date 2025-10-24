package io.contexa.contexacommon.domain;

/**
 * IAM 연구소 전문 분야 정의
 * 
 * 각 연구소의 전문 영역과 핵심 역량을 명확히 구분
 */
public enum LabSpecialization {
    
    /**
     * 정책 생성 및 관리 전문 연구소
     * - AI 기반 정책 자동 생성
     * - 정책 템플릿 최적화
     * - 정책 충돌 감지 및 해결
     */
    POLICY_GENERATION("Policy Generation & Management", 
                     "Advanced AI-driven policy creation and optimization"),
    
    /**
     * 위험 평가 및 분석 전문 연구소
     * - 실시간 위험 탐지
     * - 위험 패턴 분석
     * - 예측적 위험 평가
     */
    RISK_ASSESSMENT("Risk Assessment & Analysis", 
                   "Comprehensive risk evaluation and predictive analysis"),
    
    /**
     * 👤 사용자 행동 분석 전문 연구소
     * - 사용자 패턴 분석
     * - 이상 행동 탐지
     * - 개인화된 보안 추천
     */
    USER_BEHAVIOR_ANALYSIS("User Behavior Analysis", 
                          "Deep user pattern analysis and anomaly detection"),
    
    /**
     * 접근 제어 최적화 전문 연구소
     * - 동적 접근 제어
     * - 권한 최적화
     * - 제로 트러스트 구현
     */
    ACCESS_CONTROL_OPTIMIZATION("Access Control Optimization", 
                               "Dynamic access control and zero-trust implementation"),
    
    /**
     * 감사 및 컴플라이언스 전문 연구소
     * - 자동 감사 로그 분석
     * - 컴플라이언스 검증
     * - 규정 준수 모니터링
     */
    AUDIT_COMPLIANCE("Audit & Compliance", 
                    "Automated audit analysis and compliance verification"),
    
    /**
     * AI 모델 통합 및 최적화 전문 연구소
     * - AI 모델 성능 튜닝
     * - 모델 간 협업 최적화
     * - 실시간 모델 업데이트
     */
    AI_MODEL_OPTIMIZATION("AI Model Integration & Optimization", 
                         "Advanced AI model tuning and collaborative optimization"),
    
    /**
     * 보안 인텔리전스 전문 연구소
     * - 위협 인텔리전스 분석
     * - 보안 이벤트 상관관계 분석
     * - 사이버 위협 예측
     */
    SECURITY_INTELLIGENCE("Security Intelligence", 
                         "Threat intelligence and cyber security prediction"),
    
    /**
     * 보안 분석 전문 연구소
     * - 종합적 보안 분석
     * - 보안 패턴 인식
     * - 보안 상태 평가
     */
    SECURITY_ANALYSIS("Security Analysis",
                     "Comprehensive security analysis and pattern recognition"),
    
    /**
     * 💡 추천 시스템 전문 연구소
     * - 개인화된 보안 추천
     * - 정책 추천 엔진
     * - 최적 구성 제안
     */
    RECOMMENDATION_SYSTEM("Recommendation System", 
                         "Personalized security and policy recommendations"),
    
    /**
     * 워크플로우 자동화 전문 연구소
     * - 자동화 워크플로우 설계
     * - 프로세스 최적화
     * - 통합 오케스트레이션
     */
    WORKFLOW_AUTOMATION("Workflow Automation", 
                       "Intelligent workflow design and process optimization"),
    
    /**
     * 데이터 분석 및 인사이트 전문 연구소
     * - 빅데이터 분석
     * - 패턴 인식
     * - 예측 분석
     */
    DATA_ANALYTICS("Data Analytics & Insights", 
                  "Advanced data analysis and predictive insights"),
    
    // ========================================
    // 🏛️ Authorization Studio 전문 연구소들
    // ========================================
    
    /**
     * Authorization Studio 자연어 질의 전문 연구소
     * - 자연어 권한 질의 처리
     * - 권한 구조 인사이트 제공
     * - 시각화 데이터 생성
     */
    STUDIO_QUERY("Studio Natural Language Query", 
                "Authorization Studio natural language query processing and insights"),
    
    /**
     * Authorization Studio 리스크 분석 전문 연구소
     * - 권한 이상 탐지
     * - 리스크 평가 및 분석
     * - 컴플라이언스 모니터링
     */
    STUDIO_RISK_ANALYSIS("Studio Risk Analysis", 
                        "Authorization Studio risk assessment and anomaly detection"),
    
    /**
     * 💡 Authorization Studio 권한 추천 전문 연구소
     * - 스마트 권한 추천
     * - 최소 권한 원칙 적용
     * - 역할 기반 권한 최적화
     */
    STUDIO_PERMISSION_RECOMMENDATION("Studio Permission Recommendation", 
                                   "Authorization Studio smart permission recommendations"),
    
    /**
     * Authorization Studio 대화형 관리 전문 연구소
     * - 자연어 명령 처리
     * - 대화형 권한 관리
     * - 음성 기반 인터페이스
     */
    STUDIO_CONVERSATION("Studio Conversational Management", 
                       "Authorization Studio conversational permission management"),

    SECURITY_RESPONSE("Studio Conversational Management",
            "Authorization Studio conversational permission management");

    private final String displayName;
    private final String description;
    
    LabSpecialization(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }
    
    /**
     * 전문 분야의 표시 이름을 반환합니다
     */
    public String getDisplayName() {
        return displayName;
    }
    
    /**
     * 전문 분야의 상세 설명을 반환합니다
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * 전문 분야의 우선순위를 반환합니다 (낮을수록 높은 우선순위)
     */
    public int getPriority() {
        return switch (this) {
            case SECURITY_INTELLIGENCE -> 1;
            case SECURITY_ANALYSIS -> 1;
            case RISK_ASSESSMENT -> 2;
            case ACCESS_CONTROL_OPTIMIZATION -> 3;
            case POLICY_GENERATION -> 4;
            case USER_BEHAVIOR_ANALYSIS -> 5;
            case AUDIT_COMPLIANCE -> 6;
            case AI_MODEL_OPTIMIZATION -> 7;
            case RECOMMENDATION_SYSTEM -> 8;
            case WORKFLOW_AUTOMATION -> 9;
            case DATA_ANALYTICS -> 10;
            case SECURITY_RESPONSE -> 11;
            // Authorization Studio 특화 랩들
            case STUDIO_QUERY -> 3;
            case STUDIO_RISK_ANALYSIS -> 2;
            case STUDIO_PERMISSION_RECOMMENDATION -> 4;
            case STUDIO_CONVERSATION -> 5;
        };
    }
}