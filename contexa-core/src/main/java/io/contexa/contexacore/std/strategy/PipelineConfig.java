package io.contexa.contexacore.std.strategy;

import lombok.Builder;
import lombok.Getter;


@Getter
@Builder
public class PipelineConfig {

    
    private final ContextRetrievalStrategy contextRetrieval;

    
    private final PostProcessingStrategy postProcessing;

    
    @Builder.Default
    private final int timeoutSeconds = 300;

    
    private final String description;

    
    public enum ContextRetrievalStrategy {
        
        ALWAYS_REQUIRED,

        
        DYNAMIC,

        
        OPTIONAL
    }

    
    public enum PostProcessingStrategy {
        
        ALWAYS,

        
        DYNAMIC,

        
        FAST_PATH
    }

    
    public static PipelineConfig defaultConfig() {
        return PipelineConfig.builder()
                .contextRetrieval(ContextRetrievalStrategy.DYNAMIC)
                .postProcessing(PostProcessingStrategy.DYNAMIC)
                .description("기본 동적 구성")
                .build();
    }

    
    public static PipelineConfig fullPipeline() {
        return PipelineConfig.builder()
                .contextRetrieval(ContextRetrievalStrategy.ALWAYS_REQUIRED)
                .postProcessing(PostProcessingStrategy.ALWAYS)
                .description("전체 파이프라인")
                .build();
    }

    
    public static PipelineConfig fastResponse() {
        return PipelineConfig.builder()
                .contextRetrieval(ContextRetrievalStrategy.OPTIONAL)
                .postProcessing(PostProcessingStrategy.FAST_PATH)
                .description("빠른 응답")
                .build();
    }
}
