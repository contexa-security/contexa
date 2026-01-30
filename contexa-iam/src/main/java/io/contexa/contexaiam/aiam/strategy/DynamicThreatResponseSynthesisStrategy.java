package io.contexa.contexaiam.aiam.strategy;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import io.contexa.contexacore.std.strategy.PipelineConfig;
import io.contexa.contexaiam.aiam.labs.synthesis.DynamicThreatResponseSynthesisLab;
import io.contexa.contexaiam.aiam.protocol.context.DynamicThreatResponseContext;
import io.contexa.contexaiam.aiam.protocol.request.DynamicThreatResponseRequest;
import io.contexa.contexaiam.aiam.protocol.response.DynamicThreatResponseResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.enums.DiagnosisType;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
public class DynamicThreatResponseSynthesisStrategy extends AbstractAIStrategy<DomainContext, DynamicThreatResponseResponse> {
    
    public DynamicThreatResponseSynthesisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }
    
    @Override
    public DiagnosisType getSupportedType() {
        return DiagnosisType.THREAT_RESPONSE;
    }
    
    @Override
    public int getPriority() {
        return 20;  
    }
    
    @Override
    public boolean supportsStreaming() {
        return true;
    }
    
    @Override
    protected void validateRequest(AIRequest<DomainContext> request) throws DiagnosisException {
        if (request == null) {
            throw new DiagnosisException("THREAT_RESPONSE", "NULL_REQUEST", "요청이 null입니다");
        }

        Object threatInfo = request.getParameter("threatInfo", Object.class);
        if (threatInfo == null) {
            throw new DiagnosisException("THREAT_RESPONSE", "MISSING_THREAT_INFO",
                    "threatInfo 파라미터가 필요합니다");
        }

        Object responseInfo = request.getParameter("responseInfo", Object.class);
        if (responseInfo == null) {
            throw new DiagnosisException("THREAT_RESPONSE", "MISSING_RESPONSE_INFO",
                    "responseInfo 파라미터가 필요합니다");
        }
    }
    
    @Override
    protected Class<?> getLabType() {
        return DynamicThreatResponseSynthesisLab.class;
    }
    
    @Override
    protected Object buildLabRequest(AIRequest<DomainContext> request) {
        
        DynamicThreatResponseContext context = new DynamicThreatResponseContext();

        if (request.getContext() != null) {
            context.setUserId(request.getContext().getUserId());
            context.setSessionId(request.getContext().getSessionId());
        }

        String eventId = request.getParameter("eventId", String.class);
        if (eventId != null) {
            context.setEventId(eventId);
        }

        return DynamicThreatResponseRequest.create(context);
    }
    
    @Override
    protected DynamicThreatResponseResponse processLabExecution(
            Object lab, 
            Object labRequest, 
            AIRequest<DomainContext> request) throws Exception {
        
        AILab<DynamicThreatResponseRequest, DynamicThreatResponseResponse> synthesisLab = 
                (DynamicThreatResponseSynthesisLab) lab;
        DynamicThreatResponseRequest synthesisRequest = (DynamicThreatResponseRequest) labRequest;
        
                return synthesisLab.process(synthesisRequest);
    }
    
    @Override
    protected Mono<DynamicThreatResponseResponse> processLabExecutionAsync(
            Object lab, 
            Object labRequest, 
            AIRequest<DomainContext> originRequest) {
        
        AILab<DynamicThreatResponseRequest, DynamicThreatResponseResponse> synthesisLab = 
                (DynamicThreatResponseSynthesisLab) lab;
        DynamicThreatResponseRequest synthesisRequest = (DynamicThreatResponseRequest) labRequest;
        
                return synthesisLab.processAsync(synthesisRequest);
    }
    
    @Override
    protected Flux<String> processLabExecutionStream(
            Object lab, 
            Object labRequest, 
            AIRequest<DomainContext> request) {
        
        AILab<DynamicThreatResponseRequest, DynamicThreatResponseResponse> synthesisLab = 
                (DynamicThreatResponseSynthesisLab) lab;
        DynamicThreatResponseRequest synthesisRequest = (DynamicThreatResponseRequest) labRequest;
        
                return synthesisLab.processStream(synthesisRequest);
    }
    
    @Override
    protected String getExecutionErrorMessage() {
        return "동적 위협 대응 합성 실행 실패: ";
    }
    
    @Override
    protected String getAsyncExecutionErrorMessage() {
        return "비동기 동적 위협 대응 합성 실행 실패: ";
    }

    public boolean canHandle(AIRequest<DomainContext> request) {
        if (request == null) return false;

        return request.getParameter("threatInfo", Object.class) != null &&
               request.getParameter("responseInfo", Object.class) != null;
    }

    @Override
    protected PipelineConfig getPipelineConfig() {
        
        return PipelineConfig.fullPipeline();
    }
}