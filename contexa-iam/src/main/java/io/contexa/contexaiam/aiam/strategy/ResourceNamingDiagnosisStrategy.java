package io.contexa.contexaiam.aiam.strategy;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.analyzer.RequestCharacteristics;
import io.contexa.contexacore.std.pipeline.condition.AlwaysExecuteCondition;
import io.contexa.contexacore.std.pipeline.condition.ContextRetrievalOptionalCondition;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import io.contexa.contexaiam.aiam.labs.resource.ResourceNamingLab;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNamingSuggestionRequest;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * 리소스 네이밍 진단 전략 (리팩토링 버전)
 *
 * 기존 ResourceNamingDiagnosisStrategy의 모든 기능을 유지하면서
 * 새로운 추상 클래스 구조를 활용하여 중복 코드 제거
 */
@Slf4j
@Component
public class ResourceNamingDiagnosisStrategy extends AbstractAIStrategy<ResourceNamingContext, ResourceNamingSuggestionResponse> {

    public ResourceNamingDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }

    @Override
    public DiagnosisType getSupportedType() {
        return DiagnosisType.RESOURCE_NAMING;
    }

    @Override
    public int getPriority() {
        return 10; // 높은 우선순위 (기존과 동일)
    }

    @Override
    protected void validateRequest(AIRequest<ResourceNamingContext> request) throws DiagnosisException {
        List<Map<String, String>> resources = (List<Map<String, String>>) request.getParameter("resources", List.class);

        if (resources == null || resources.isEmpty()) {
            throw new DiagnosisException("RESOURCE_NAMING", "MISSING_RESOURCES",
                    "resources 파라미터가 필요합니다");
        }
    }

    @Override
    protected Class<?> getLabType() {
        return ResourceNamingLab.class;
    }

    @Override
    protected Object buildLabRequest(AIRequest<ResourceNamingContext> request) throws DiagnosisException {
        try {
            List<Map<String, String>> legacyResources = (List<Map<String, String>>) request.getParameter("resources", List.class);
            return ResourceNamingSuggestionRequest.fromMapList(legacyResources);

        } catch (ClassCastException e) {
            throw new DiagnosisException("RESOURCE_NAMING", "INVALID_RESOURCES_FORMAT",
                    "resources 파라미터 형식이 올바르지 않습니다", e);
        }
    }

    @Override
    protected ResourceNamingSuggestionResponse processLabExecution(Object lab, Object labRequest, AIRequest<ResourceNamingContext> request) throws Exception {
        AILab<ResourceNamingSuggestionRequest, ResourceNamingSuggestionResponse> resourceNamingLab = (ResourceNamingLab) lab;
        ResourceNamingSuggestionRequest namingRequest = (ResourceNamingSuggestionRequest) labRequest;
        ResourceNamingSuggestionResponse namingResponse = resourceNamingLab.process(namingRequest);
        log.debug("Lab 응답을 직접 반환: suggestions={}", namingResponse.getSuggestions().size());

        return namingResponse;
    }

    @Override
    protected Mono<ResourceNamingSuggestionResponse> processLabExecutionAsync(Object lab, Object labRequest, AIRequest<ResourceNamingContext> originRequest) {
        AILab<ResourceNamingSuggestionRequest, ResourceNamingSuggestionResponse> resourceNamingLab = (ResourceNamingLab) lab;
        ResourceNamingSuggestionRequest namingRequest = (ResourceNamingSuggestionRequest) labRequest;

        log.info("비동기 리소스 명명 요청 처리 시작");
        return resourceNamingLab.processAsync(namingRequest);
    }

    // getPipelineConfig()를 오버라이드하지 않음
    // AbstractAIStrategy의 기본 동적 로직(PipelineConfig.defaultConfig())을 사용
    // 복잡도에 따라 자동으로 컨텍스트 조회 및 후처리 결정
}