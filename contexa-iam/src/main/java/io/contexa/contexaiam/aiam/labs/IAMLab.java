package io.contexa.contexaiam.aiam.labs;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacommon.domain.LabSpecialization;

/**
 * IAM 도메인 특화 Lab 인터페이스
 *
 * AILab을 IAM 도메인에 특화시킨 인터페이스
 * 모든 IAM 관련 Lab이 이 인터페이스를 구현
 *
 * @param <R> 요청 타입
 */
public interface IAMLab<Req, Res> extends AILab<Req, Res> {

    /**
     * Lab의 전문 분야 반환
     * 기존 LabSpecialization과 호환
     */
    LabSpecialization getSpecialization();

    /**
     * Lab의 버전 정보 반환
     */
    default String getVersion() {
        return "1.0.0";
    }
}