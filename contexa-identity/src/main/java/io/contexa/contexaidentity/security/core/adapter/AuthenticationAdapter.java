package io.contexa.contexaidentity.security.core.adapter;

import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

/**
 * 개별 인증 단계(예: Form 로그인, REST 로그인, Passkey, OTT 등)의
 * HttpSecurity 구성 로직을 캡슐화한 기능 인터페이스입니다.
 *
 * 각 구현체는 자신의 인증 방식에 맞추어
 * HttpSecurity에 필터 추가, 엔드포인트 설정, 핸들러 지정 등을 수행합니다.
 */
public interface AuthenticationAdapter {

    /**
     * 인증 기능의 고유 식별자(ID)를 반환합니다 (예: "form", "rest", etc.)
     */
    String getId();

    /**
     * 인증 기능 실행 순서를 지정합니다.
     */
    int getOrder();

    /**
     * 주어진 HttpSecurity, 인증 단계 설정(steps), 최종 상태(state)를 기반으로
     * 자신만의 인증 로직을 구성합니다.
     *
     * @param http   HttpSecurity 인스턴스
     * @param steps  DSL로 정의된 인증 단계 설정 리스트
     * @param state  최종 인증 상태 설정
     * @throws Exception 구성 중 오류 발생 시
     */
    void apply(HttpSecurity http, List<AuthenticationStepConfig> steps, StateConfig state) throws Exception;
}

