package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexacommon.domain.response.IAMResponse;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * AI-Native Authorization Studio 질의 응답 클래스
 * 
 * 기존 프로토콜 구조 완전 준수
 * Mermaid 시각화 데이터 포함
 * 클라이언트 다국어화 지원
 */
@Getter
@Setter
public class StudioQueryResponse extends IAMResponse {
    
    /**
     * 자연어 답변 (AI가 생성한 텍스트 응답)
     */
    private String naturalLanguageAnswer;
    
    /**
     * 질의 결과 목록
     */
    private List<QueryResult> queryResults = new ArrayList<>();
    
    /**
     * 구조화된 분석 결과 (사용자별 권한 분석)
     */
    private List<AnalysisResult> analysisResults = new ArrayList<>();
    
    /**
     * 시각화 데이터 (Mermaid 등을 위한)
     */
    private VisualizationData visualizationData;
    
    /**
     * AI 권장사항
     */
    private List<Recommendation> recommendations = new ArrayList<>();
    
    /**
     * 처리 시간 (밀리초)
     */
    private long processingTimeMs;
    
    /**
     * 신뢰도 점수 설정 (0-100)
     */
    public void setConfidenceScore(int score) {
        this.withConfidenceScore(score / 100.0);
    }
    
    public StudioQueryResponse(String requestId) {
        super(requestId, ExecutionStatus.SUCCESS);
    }

    public StudioQueryResponse(String requestId, ExecutionStatus status) {
        super(requestId, status);
    }

    
    public StudioQueryResponse() {
        super("default", ExecutionStatus.SUCCESS);
    }
    
    @Override
    public String getResponseType() {
        return "STUDIO_QUERY";
    }
    
    @Override
    public Object getData() {
        Map<String, Object> data = new HashMap<>();
        data.put("naturalLanguageAnswer", naturalLanguageAnswer);
        data.put("queryResults", queryResults);
        data.put("analysisResults", analysisResults);
        data.put("visualizationData", visualizationData);
        data.put("recommendations", recommendations);
        data.put("confidenceScore", getConfidenceScore());
        data.put("processingTimeMs", processingTimeMs);
        return data;
    }
    
    /**
     * 질의 결과 개수를 반환합니다
     */
    public int getResultCount() {
        return queryResults != null ? queryResults.size() : 0;
    }
    
    /**
     * 질의 결과 개별 항목
     */
    @Getter
    @Setter
    public static class QueryResult {
        private String entity;           // 엔티티명 (사용자명, 역할명 등)
        private String actionType;       // 액션 타입 (READ, WRITE, DELETE 등)
        private String description;      // 설명
        private int relevanceScore;      // 관련도 점수 (0-100)
        private Map<String, Object> metadata = new HashMap<>();
    }
    
    /**
     * 구조화된 분석 결과 (사용자별 권한 분석)
     */
    @Getter
    @Setter
    public static class AnalysisResult {
        private String user;         // 구체적인 사용자명
        private List<String> groups;        // 그룹명
        private List<String> roles;         // 역할명
        private List<String> permissions;   // 권한명
        private boolean hasPermission;   // 권한 보유 여부
        private String description;      // 해당 사용자의 권한 상세 설명
        private Map<String, Object> metadata = new HashMap<>();
    }
    
    /**
     * 🎨 시각화 데이터
     */
    @Getter
    @Setter
    public static class VisualizationData {
        private String graphType;         // NETWORK, HIERARCHY, FLOWCHART, MATRIX
        private String title;            // 시각화 제목
        private String description;      // 시각화 설명
        private List<Node> nodes = new ArrayList<>();
        private List<Edge> edges = new ArrayList<>();
        private Map<String, Object> layoutConfig = new HashMap<>();
        private Map<String, String> styling = new HashMap<>();
        
        @Getter
        @Setter
        public static class Node {
            private String id;
            private String label;
            private String type;
            private String category;
            private String color;        // 노드 색상
            private boolean highlighted = false;
            private Map<String, Object> properties = new HashMap<>();
            private Map<String, Object> metadata = new HashMap<>();
        }
        
        @Getter
        @Setter
        public static class Edge {
            private String id;
            private String source;
            private String target;
            private String relationship;
            private String label;
            private String type;         // 엣지 타입
            private String color;        // 엣지 색상
            private boolean highlighted = false;
            private boolean dashed = false; // 점선 여부
            private Map<String, Object> properties = new HashMap<>();
        }
    }
    
    /**
     * 🔮 AI 권장사항
     */
    @Getter
    @Setter
    public static class Recommendation {
        private String title;            // 권장사항 제목
        private String description;      // 권장사항 설명
        private int priority = 2;        // 우선순위 (1:높음, 2:보통, 3:낮음)
        private String category;        // 카테고리 (SECURITY, COMPLIANCE, PERFORMANCE 등)
        private String type;            // 타입 (category와 동일하게 사용)
        private List<String> actionItems = new ArrayList<>(); // 실행 가능한 액션 아이템들
        private List<ActionLink> actionLinks = new ArrayList<>(); // 실행 가능한 액션 링크들
        private Map<String, Object> metadata = new HashMap<>();
        
        public void setType(String type) {
            this.type = type;
            this.category = type; // type과 category를 동일하게 처리
        }
    }
    
    /**
     * 🔗 실행 가능한 액션 링크
     */
    @Getter
    @Setter
    public static class ActionLink {
        private String text;            // 버튼에 표시될 텍스트
        private String url;             // 이동할 URL
        private String type;            // 버튼 타입 (PRIMARY, SECONDARY, DANGER 등)
        private String icon;            // 아이콘 클래스
        private boolean openInNewTab = false;  // 새 탭에서 열기 여부
        private Map<String, Object> metadata = new HashMap<>();
    }
    
    /**
     * 성공 응답 생성 헬퍼
     */
    public static StudioQueryResponse success(String requestId, String answer) {
        StudioQueryResponse response = new StudioQueryResponse(requestId);
        response.setNaturalLanguageAnswer(answer);
        return response;
    }
    
    /**
     * 실패 응답 생성 헬퍼
     */
    public static StudioQueryResponse failure(String requestId, String errorMessage) {
        StudioQueryResponse response = new StudioQueryResponse(requestId);
        return (StudioQueryResponse) response.withError(errorMessage);
    }
    
    /**
     * 오류 응답 생성 헬퍼 (파서용)
     */
    public static StudioQueryResponse error(String requestId, String errorMessage) {
        StudioQueryResponse response = new StudioQueryResponse(requestId);
        return (StudioQueryResponse) response.withError(errorMessage);
    }
} 