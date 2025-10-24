package io.contexa.contexaiam.aiam.strategy;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import io.contexa.contexacore.std.strategy.PipelineConfig;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.analyzer.RequestCharacteristics;
import io.contexa.contexacore.std.pipeline.condition.AlwaysExecuteCondition;
import io.contexa.contexaiam.aiam.labs.synthesis.DynamicThreatResponseSynthesisLab;
import io.contexa.contexaiam.aiam.protocol.context.DynamicThreatResponseContext;
import io.contexa.contexaiam.aiam.protocol.request.DynamicThreatResponseRequest;
import io.contexa.contexaiam.aiam.protocol.response.DynamicThreatResponseResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.enums.DiagnosisType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * 동적 위협 대응 합성 전략
 * 
 * DynamicThreatResponseSynthesisLab을 실행하는 전략 구현
 * AbstractAIStrategy를 확장하여 표준 패턴 준수
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Component
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
        return 20;  // 높은 우선순위
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
        
        // 위협 정보 검증
        Object threatInfo = request.getParameter("threatInfo", Object.class);
        if (threatInfo == null) {
            throw new DiagnosisException("THREAT_RESPONSE", "MISSING_THREAT_INFO",
                    "threatInfo 파라미터가 필요합니다");
        }
        
        // 대응 정보 검증
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
        // DomainContext를 DynamicThreatResponseContext로 변환
        DynamicThreatResponseContext context = new DynamicThreatResponseContext();
        
        // 원본 컨텍스트에서 정보 복사
        if (request.getContext() != null) {
            context.setUserId(request.getContext().getUserId());
            context.setSessionId(request.getContext().getSessionId());
        }
        
        // 이벤트 ID 설정
        String eventId = request.getParameter("eventId", String.class);
        if (eventId != null) {
            context.setEventId(eventId);
        }
        
        // DynamicThreatResponseRequest 생성
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
        
        log.info("동적 위협 대응 합성 요청: 이벤트 ID = {}", synthesisRequest.getEventId());
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
        
        log.info("비동기 동적 위협 대응 합성 요청: 이벤트 ID = {}", synthesisRequest.getEventId());
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
        
        log.info("스트리밍 동적 위협 대응 합성 요청: 이벤트 ID = {}", synthesisRequest.getEventId());
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
    
    /**
     * 이 전략이 처리할 수 있는 요청인지 확인
     */
    public boolean canHandle(AIRequest<DomainContext> request) {
        if (request == null) return false;

        // 위협 관련 파라미터가 있는지 확인
        return request.getParameter("threatInfo", Object.class) != null &&
               request.getParameter("responseInfo", Object.class) != null;
    }

    @Override
    protected PipelineConfig getPipelineConfig() {
        // 위협 대응 합성은 신속하고 정확한 대응이 필요하므로 전체 파이프라인 실행
        return PipelineConfig.fullPipeline();
    }
}