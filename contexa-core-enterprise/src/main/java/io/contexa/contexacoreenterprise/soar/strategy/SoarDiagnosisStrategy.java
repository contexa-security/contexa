package io.contexa.contexacoreenterprise.soar.strategy;

import io.contexa.contexacore.domain.SoarRequest;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacoreenterprise.soar.lab.SoarLabImpl;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

/**
 * SOAR 진단 전략
 *
 * AbstractAIStrategy를 확장하여 SOAR 기능을 기존 AI 진단 프로세스와 완벽하게 통합합니다.
 * AILab 패턴을 활용하여 일관된 아키텍처를 유지합니다.
 */
@Slf4j
@Component
public class SoarDiagnosisStrategy extends AbstractAIStrategy<SoarContext, SoarResponse> {

    private static final int PRIORITY = 10; // 높은 우선순위
    private static final boolean SUPPORTS_STREAMING = true;

    public SoarDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
        log.info("SOAR 진단 전략 초기화 완료");
    }

    @Override
    public DiagnosisType getSupportedType() {
        return DiagnosisType.SOAR;
    }

    @Override
    public boolean canHandle(AIRequest<SoarContext> request) {
        if (request == null || request.getContext() == null) {
            return false;
        }

        DiagnosisType type = request.getParameter("diagnosisType", DiagnosisType.class);
        return type == DiagnosisType.SOAR;
    }

    @Override
    public int getPriority() {
        return PRIORITY;
    }

    @Override
    public boolean supportsStreaming() {
        return SUPPORTS_STREAMING;
    }

    @Override
    protected void validateRequest(AIRequest<SoarContext> request) throws DiagnosisException {
        log.debug("SOAR 요청 검증 시작");

        // 필수 파라미터 검증
        if (request.getContext() == null) {
            throw new DiagnosisException(
                    DiagnosisType.SOAR.name(),
                    "INVALID_CONTEXT",
                    "SoarContext가 누락되었습니다"
            );
        }

        SoarContext context = request.getContext();

        // 세션 ID 검증
        if (context.getSessionId() == null || context.getSessionId().isEmpty()) {
            throw new DiagnosisException(
                    DiagnosisType.SOAR.name(),
                    "INVALID_SESSION",
                    "세션 ID가 누락되었습니다"
            );
        }

        // 원본 질의 검증
        if (context.getOriginalQuery() == null || context.getOriginalQuery().trim().isEmpty()) {
            throw new DiagnosisException(
                    DiagnosisType.SOAR.name(),
                    "INVALID_QUERY",
                    "질의가 비어있습니다"
            );
        }

        // 조직 ID 검증
        if (context.getOrganizationId() == null || context.getOrganizationId().isEmpty()) {
            throw new DiagnosisException(
                    DiagnosisType.SOAR.name(),
                    "INVALID_ORGANIZATION",
                    "조직 ID가 누락되었습니다"
            );
        }

        log.debug("SOAR 요청 검증 완료");
    }

    @Override
    protected Class<?> getLabType() {
        // 질의 유형에 따라 적절한 Lab 선택
        return SoarLabImpl.class;
    }

    @Override
    protected Object buildLabRequest(AIRequest<SoarContext> request) throws DiagnosisException {
        return request;
    }

    @Override
    protected SoarResponse processLabExecution(Object lab, Object labRequest, AIRequest<SoarContext> request)
            throws Exception {
        log.info("SOAR Lab 실행 시작");

        if (!(lab instanceof SoarLabImpl)) {
            throw new DiagnosisException(
                    DiagnosisType.SOAR.name(),
                    "INVALID_LAB",
                    "잘못된 Lab 타입: " + lab.getClass().getName()
            );
        }

        if (!(labRequest instanceof SoarRequest)) {
            throw new DiagnosisException(
                    DiagnosisType.SOAR.name(),
                    "INVALID_REQUEST",
                    "잘못된 요청 타입: " + labRequest.getClass().getName()
            );
        }

        SoarLabImpl soarLab = (SoarLabImpl) lab;
        SoarRequest soarRequest = (SoarRequest) labRequest;

        // Lab 실행
        SoarResponse response = soarLab.process(soarRequest);

        // 컨텍스트 업데이트
        updateContext(request.getContext(), response);

        log.info("SOAR Lab 실행 완료 - 세션: {}", soarRequest.getSessionId());
        return response;
    }

    @Override
    protected Mono<SoarResponse> processLabExecutionAsync(Object lab, Object labRequest,
                                                          AIRequest<SoarContext> originRequest) {

        AILab<SoarRequest, SoarResponse> soarLab = (SoarLabImpl) lab;
        SoarRequest soarRequest = (SoarRequest) labRequest;

        log.info("비동기 정책 생성 요청: {}", soarRequest.getQuery());
        return soarLab.processAsync(soarRequest);
    }

    @Override
    protected Flux<String> processLabExecutionStream(Object lab, Object labRequest,
                                                     AIRequest<SoarContext> request) {
        AILab<SoarRequest, SoarResponse> soarLab = (SoarLabImpl) lab;
        SoarRequest soarRequest = (SoarRequest) labRequest;

        log.info("비동기 정책 생성 요청: {}", soarRequest.getQuery());
        return soarLab.processStream(soarRequest);
    }

    /**
     * 컨텍스트 업데이트
     */
    private void updateContext(SoarContext context, SoarResponse response) {
        // 대화 히스토리 업데이트
        if (response.getAnalysisResult() != null) {
            context.addConversationEntry("assistant", response.getAnalysisResult());
        }

        // 세션 상태 업데이트
        if (response.getSessionState() != null) {
            context.setSessionState(response.getSessionState());
        }

        // 마지막 활동 시간 업데이트
        context.setLastActivity(LocalDateTime.now());

        // 실행된 도구 업데이트
        if (response.getExecutedTools() != null && !response.getExecutedTools().isEmpty()) {
            response.getExecutedTools().forEach(tool ->
                    context.getApprovedTools().add(tool)
            );
        }
    }
}