package io.contexa.contexaidentity.security.core.dsl;

import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import lombok.Getter;
import org.springframework.lang.Nullable;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;

import java.util.Objects;

/**
 * 추상 DSL Configurer의 기본 동작을 제공하는 베이스 클래스.
 * 이 클래스는 AbstractOptionsBuilderConfigurer 와는 다른 계층의 Configurer 이다
 * (예: 상태 관리 Configurer - SessionStateConfigurer, JwtStateConfigurer 등)
 * @param <O> 이 Configurer가 사용하는 옵션 객체 타입 (반드시 Options 클래스는 아닐 수 있음)
 * @param <D> DSL 구현 타입 (이 클래스를 상속하는 구체적인 Configurer)
 */
@Getter
public abstract class AbstractDslConfigurer<O, D extends CommonSecurityDsl<D>> implements CommonSecurityDsl<D> {

    protected final AuthenticationStepConfig stepConfig; // 이 필드가 모든 하위 클래스에 필요한지 확인 필요

    protected final O options; // 이 Configurer가 사용하는 옵션 객체
    protected int order = 10; // 기본 순서

    protected AbstractDslConfigurer(O options) {
        this(null, options);
    }

    protected AbstractDslConfigurer(@Nullable AuthenticationStepConfig stepConfig, O options) {
        this.stepConfig = stepConfig; // null일 수 있음
        this.options = Objects.requireNonNull(options, "options must not be null");
    }

    /**
     * 생성된 stepConfig를 반환합니다. MFA Step과 관련 없는 Configurer 에서는 null일 수 있습니다.
     * @return AuthenticationStepConfig 또는 null
     */
    @Nullable
    public AuthenticationStepConfig getStepConfig() { // 메소드명 변경
        return stepConfig;
    }

    @Override
    public D disableCsrf() {
        return (D) this;
    }

    @Override
    public D cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        return (D) this;
    }

    @Override
    public D headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        return (D) this;
    }

    @Override
    public D sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        return (D) this;
    }

    @Override
    public D logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        return (D) this;
    }
}