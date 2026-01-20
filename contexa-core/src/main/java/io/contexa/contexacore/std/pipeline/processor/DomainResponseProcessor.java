package io.contexa.contexacore.std.pipeline.processor;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;


public interface DomainResponseProcessor {
    
    
    boolean supports(String templateKey);
    
    
    boolean supportsType(Class<?> responseType);
    
    
    Object wrapResponse(Object parsedData, PipelineExecutionContext context);
    
    
    default int getOrder() {
        return 0;
    }
}