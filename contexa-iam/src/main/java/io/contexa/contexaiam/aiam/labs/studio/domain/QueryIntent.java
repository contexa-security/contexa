package io.contexa.contexaiam.aiam.labs.studio.domain;

import lombok.Data;
import java.util.ArrayList;
import java.util.List;

/**
 * AI 기반 질의 의도 분석 결과
 * 
 * 자연어 질의를 AI가 분석한 의도와 맥락 정보
 * 하드코딩 대신 동적 패턴 분석 결과
 */
@Data
public class QueryIntent {
    
    /**
     * 원본 질의
     */
    private String originalQuery;
    
    /**
     * AI가 분석한 질의 타입
     */
    private String queryType;
    
    /**
     * 대상 엔티티 목록
     */
    private List<String> targetEntities = new ArrayList<>();
    
    /**
     * 분석 범위
     */
    private String analysisScope;
    
    /**
     * 포커스 영역
     */
    private String focusArea;
    
    /**
     * 질의 의도 신뢰도 (0.0 ~ 1.0)
     */
    private double intentConfidence = 0.0;
    
    /**
     * 추출된 키워드 목록
     */
    private List<String> extractedKeywords = new ArrayList<>();
    
    /**
     * 질의 복잡도 (0.0 ~ 1.0)
     */
    private double queryComplexity = 0.0;
    
    // ============================= 
    // 추가 메서드들
    // ============================= 
    
    /**
     * 질의 타입 반환 (별칭)
     */
    public String getQuestionType() {
        return this.queryType;
    }
    
    /**
     * 주요 엔티티 타입 반환
     */
    public String getEntityType() {
        return targetEntities.isEmpty() ? "UNKNOWN" : targetEntities.get(0);
    }
    
    /**
     * 타입 기반 QueryIntent 생성
     */
    public static QueryIntent findByTypes(String questionType, String entityType) {
        QueryIntent intent = new QueryIntent();
        intent.setQueryType(questionType);
        intent.getTargetEntities().add(entityType);
        intent.setIntentConfidence(0.8); // 기본 신뢰도
        return intent;
    }
} 