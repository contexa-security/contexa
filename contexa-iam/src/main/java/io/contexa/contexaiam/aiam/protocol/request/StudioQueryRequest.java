package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexacommon.domain.request.IAMRequest;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Map;

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

    public static StudioQueryRequest quickQuery(String query, String queryType, String userId) {
        StudioQueryRequest request = new StudioQueryRequest();
        request.setQuery(query);
        request.setQueryType(queryType);
        request.setUserId(userId);
        request.setTimestamp(LocalDateTime.now());
        request.setMetadata(new java.util.HashMap<>());
        return request;
    }

    public boolean isValid() {
        return query != null && !query.trim().isEmpty() && 
               userId != null && !userId.trim().isEmpty();
    }

    public String getRequestId() {
        if (metadata != null && metadata.containsKey("requestId")) {
            return (String) metadata.get("requestId");
        }
        
        return "req-" + System.currentTimeMillis();
    }
} 