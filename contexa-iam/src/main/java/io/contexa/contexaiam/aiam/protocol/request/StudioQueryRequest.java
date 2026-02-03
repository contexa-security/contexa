package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Map;

@Getter
@Setter
public class StudioQueryRequest extends AIRequest<StudioQueryContext> {
    
    private String userId;
    private LocalDateTime timestamp;
    private Map<String, Object> metadata;

    public StudioQueryRequest(StudioQueryContext context, TemplateType templateType, DiagnosisType diagnosisType) {
        super(context, templateType, diagnosisType);
    }


} 