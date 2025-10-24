package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexacommon.domain.request.IAMRequest;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * AI-Native Authorization Studio 질의 요청 클래스
 * 
 * 기존 프로토콜 구조 완전 준수
 * 클라이언트 다국어화 지원 - 서버 하드코딩 제거
 */
@Getter
@Setter
public class StudioQueryRequest  extends IAMRequest<StudioQueryContext> {
    
    private String query;
    private String queryType;
    private String userId;
    private LocalDateTime timestamp;
    private Map<String, Object> metadata;

    public StudioQueryRequest() {
        this(null, null);
    }

    public StudioQueryRequest(StudioQueryContext context, String operation) {
        super(context, operation);
    }

    /**
     * 빠른 질의 생성 헬퍼 메서드
     */
    public static StudioQueryRequest quickQuery(String query, String queryType, String userId) {
        StudioQueryRequest request = new StudioQueryRequest();
        request.setQuery(query);
        request.setQueryType(queryType);
        request.setUserId(userId);
        request.setTimestamp(LocalDateTime.now());
        request.setMetadata(new java.util.HashMap<>());
        return request;
    }
    
    /**
     * 질의 내용 유효성 검증
     */
    public boolean isValid() {
        return query != null && !query.trim().isEmpty() && 
               userId != null && !userId.trim().isEmpty();
    }
    
    /**
     * 요청 ID 반환 (메타데이터에서 추출 또는 생성)
     */
    public String getRequestId() {
        if (metadata != null && metadata.containsKey("requestId")) {
            return (String) metadata.get("requestId");
        }
        // 요청 ID가 없으면 타임스탬프 기반으로 생성
        return "req-" + System.currentTimeMillis();
    }
} 