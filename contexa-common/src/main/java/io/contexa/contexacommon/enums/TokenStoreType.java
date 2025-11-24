package io.contexa.contexacommon.enums;

/**
 * 토큰 저장소 타입을 정의하는 Enum
 *
 * @since 2024.12
 * @author Spring Security 6.x Platform Team
 */
public enum TokenStoreType {
    /**
     * 메모리 기반 토큰 저장소
     * - 단일 서버 환경에 적합
     * - 서버 재시작 시 모든 토큰 정보 손실
     * - 빠른 응답 속도
     */
    MEMORY,

    /**
     * Redis 기반 토큰 저장소
     * - 분산 서버 환경에 적합
     * - 서버 재시작에도 토큰 정보 유지
     * - 수평 확장성 제공
     * - 토큰 만료 시간 자동 관리 (TTL)
     */
    REDIS
}
