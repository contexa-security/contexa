package io.contexa.contexaidentity.security.core.config;

import io.contexa.contexacommon.enums.StateType;

/**
 * 인증 후 상태 관리 전략 설정을 담는 설정 객체입니다.
 *
 * @param state 상태 전략 ID ("session", "jwt", "oauth2")
 * @param stateType 상태 타입 열거형
 */
public record StateConfig(String state, StateType stateType) {
}

