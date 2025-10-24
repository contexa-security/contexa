package io.contexa.contexaiam.aiam.labs;

import io.opentelemetry.api.trace.Tracer;
import io.contexa.contexacore.std.labs.AbstractAILab;
import io.contexa.contexacommon.domain.LabSpecialization;
import lombok.extern.slf4j.Slf4j;

/**
 * IAM 도메인 Lab 추상 클래스
 *
 * IAM 도메인의 모든 Lab이 공유하는 공통 로직
 * 기존 AbstractIAMLab을 대체하는 새로운 버전
 *
 * @param <R> 요청 타입
 */
@Slf4j
public abstract class AbstractIAMLab<Req,Res> extends AbstractAILab<Req, Res> implements IAMLab<Req,Res> {

    private final String labVersion;
    private final LabSpecialization specialization;

    // AbstractAILab은 Tracer를 받으므로 그대로 전달
    protected AbstractIAMLab(Tracer tracer, String labName, String labVersion, LabSpecialization specialization) {
        super(labName, tracer);  // AbstractAILab(String labName, Tracer tracer) 호출
        this.labVersion = labVersion;
        this.specialization = specialization;
    }

    @Override
    public LabSpecialization getSpecialization() {
        return specialization;
    }

    @Override
    public String getVersion() {
        return labVersion;
    }

    /**
     * IAM 특화: 응답에 기본 정보 설정
     */
    @Override
    protected void postProcess(Req request, Res result) {
        super.postProcess(request, result);

        // IAM 특화 후처리 (필요시)
        if (result != null) {
            log.debug("IAM Lab {} processed request with result type: {}",
                    getLabName(), result.getClass().getSimpleName());
        }
    }
}
