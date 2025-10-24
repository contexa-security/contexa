package io.contexa.contexacore.std.pipeline.builder;

import io.contexa.contexacore.std.pipeline.step.PipelineStep;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * 커스텀 파이프라인 단계 등록소
 *
 * 사용자 정의 파이프라인 단계를 등록하고 조회할 수 있습니다.
 * Spring Bean으로 등록되어 애플리케이션 전역에서 사용 가능합니다.
 *
 * 사용 예시:
 * - 행동 패턴 추출 단계 등록
 * - 신뢰도 점수 계산 단계 등록
 * - 도메인별 특화 처리 단계 등록
 */
@Component
@Slf4j
public class CustomPipelineStepRegistry {

    private final Map<String, PipelineStep> customSteps = new ConcurrentHashMap<>();

    /**
     * 커스텀 단계 등록
     *
     * @param stepName 단계 이름 (고유 식별자)
     * @param step 파이프라인 단계 구현체
     */
    public void registerCustomStep(String stepName, PipelineStep step) {
        if (stepName == null || stepName.trim().isEmpty()) {
            throw new IllegalArgumentException("Step name cannot be null or empty");
        }
        if (step == null) {
            throw new IllegalArgumentException("Step cannot be null");
        }

        customSteps.put(stepName, step);
        log.info("[CustomStepRegistry] 커스텀 단계 등록: {} (order: {})",
                stepName, step.getOrder());
    }

    /**
     * 커스텀 단계 조회
     *
     * @param stepName 단계 이름
     * @return 파이프라인 단계 (없으면 empty)
     */
    public Optional<PipelineStep> getCustomStep(String stepName) {
        return Optional.ofNullable(customSteps.get(stepName));
    }

    /**
     * 등록된 커스텀 단계 개수
     *
     * @return 커스텀 단계 개수
     */
    public int getCustomStepCount() {
        return customSteps.size();
    }

    /**
     * 커스텀 단계 등록 여부 확인
     *
     * @param stepName 단계 이름
     * @return 등록 여부
     */
    public boolean hasCustomStep(String stepName) {
        return customSteps.containsKey(stepName);
    }

    /**
     * 모든 커스텀 단계 조회
     *
     * @return 커스텀 단계 맵
     */
    public Map<String, PipelineStep> getAllCustomSteps() {
        return Map.copyOf(customSteps);
    }

    /**
     * 커스텀 단계 제거
     *
     * @param stepName 단계 이름
     * @return 제거 성공 여부
     */
    public boolean removeCustomStep(String stepName) {
        boolean removed = customSteps.remove(stepName) != null;
        if (removed) {
            log.info("[CustomStepRegistry] 커스텀 단계 제거: {}", stepName);
        }
        return removed;
    }

    /**
     * 모든 커스텀 단계 초기화
     */
    public void clearAllCustomSteps() {
        int count = customSteps.size();
        customSteps.clear();
        log.info("[CustomStepRegistry] 모든 커스텀 단계 초기화 ({}개)", count);
    }
}
