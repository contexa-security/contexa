package io.contexa.contexaiam.aiam.protocol.request;

import lombok.Data;

import java.time.LocalDateTime;
import java.util.Map;

@Data
public class StudioQueryItem {

    private String query;
    private String queryType;
    private String userId;
    private LocalDateTime timestamp;
    private Map<String, Object> metadata;

}