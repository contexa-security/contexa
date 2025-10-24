package io.contexa.contexaidentity.security.core.dsl.option;

import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import lombok.Getter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * 모든 인증 방식 옵션 클래스들의 공통된 기본 설정을 제공하는 추상 클래스입니다.
 * CSRF, CORS, Headers, Session Management, Logout 등 공통 보안 설정을 포함합니다.
 */
@Getter
public abstract class AbstractOptions {
    private final boolean csrfDisabled;
    private final Customizer<CorsConfigurer<HttpSecurity>> corsCustomizer;
    private final Customizer<HeadersConfigurer<HttpSecurity>> headersCustomizer;
    private final Customizer<SessionManagementConfigurer<HttpSecurity>> sessionManagementCustomizer;
    private final Customizer<LogoutConfigurer<HttpSecurity>> logoutCustomizer;
    private final List<String> staticMatchers;
    private final List<SafeHttpCustomizer<HttpSecurity>> rawHttpCustomizers;

    protected AbstractOptions(Builder<?, ?> builder) {
        Objects.requireNonNull(builder, "Builder cannot be null");
        this.csrfDisabled = builder.csrfDisabled;
        this.corsCustomizer = builder.corsCustomizer; // Optional.ofNullable(builder.corsCustomizer);
        this.headersCustomizer = builder.headersCustomizer;
        this.sessionManagementCustomizer = builder.sessionManagementCustomizer;
        this.logoutCustomizer = builder.logoutCustomizer;
        this.staticMatchers = List.copyOf(builder.staticMatchers); // Java 10+
        this.rawHttpCustomizers = List.copyOf(builder.rawHttpCustomizers); // Java 10+
    }

    /**
     * 이 옵션 객체에 정의된 공통 보안 설정을 주어진 HttpSecurity에 적용합니다.
     * @param http HttpSecurity 객체 (null이 아니어야 함)
     * @throws Exception 설정 중 발생할 수 있는 예외
     */
    public void applyCommonSecurityConfigs(HttpSecurity http) throws Exception {
        Objects.requireNonNull(http, "HttpSecurity cannot be null");

        if (csrfDisabled) {
            http.csrf(AbstractHttpConfigurer::disable);
        }
        if (corsCustomizer != null) {
            http.cors(corsCustomizer);
        }
        if (headersCustomizer != null) {
            http.headers(headersCustomizer);
        }
        if (sessionManagementCustomizer != null) {
            http.sessionManagement(sessionManagementCustomizer);
        }
        if (logoutCustomizer != null) {
            http.logout(logoutCustomizer);
        }
        if (!staticMatchers.isEmpty()) {
            http.authorizeHttpRequests(authorizeRequests -> {
                for (String matcher : staticMatchers) {
                    authorizeRequests.requestMatchers(matcher).permitAll();
                }
            });
        }
        for (SafeHttpCustomizer<HttpSecurity> rawCustomizer : rawHttpCustomizers) {
            // SafeHttpCustomizer는 예외를 던지지 않도록 설계되었다고 가정,
            // 또는 여기서 try-catch로 감싸거나 customizer.customize가 throws Exception을 선언했다면 전파
            rawCustomizer.customize(http);
        }
    }

    /**
     * AbstractOptions를 빌드하기 위한 추상 빌더 클래스입니다.
     * @param <O> 빌드될 Options의 구체적인 타입
     * @param <B> 빌더 자신의 구체적인 타입 (Self-referential)
     */
    public abstract static class Builder<O extends AbstractOptions, B extends Builder<O, B>> {
        private boolean csrfDisabled = false;
        private Customizer<CorsConfigurer<HttpSecurity>> corsCustomizer = Customizer.withDefaults();
        private Customizer<HeadersConfigurer<HttpSecurity>> headersCustomizer = Customizer.withDefaults();
        private Customizer<SessionManagementConfigurer<HttpSecurity>> sessionManagementCustomizer = Customizer.withDefaults();
        private Customizer<LogoutConfigurer<HttpSecurity>> logoutCustomizer = Customizer.withDefaults();
        private List<String> staticMatchers = Collections.emptyList();
        private final List<SafeHttpCustomizer<HttpSecurity>> rawHttpCustomizers = new ArrayList<>();

        protected abstract B self();

        public B csrfDisabled(boolean csrfDisabled) {
            this.csrfDisabled = csrfDisabled;
            return self();
        }

        public B cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
            this.corsCustomizer = Objects.requireNonNull(customizer, "corsCustomizer cannot be null");
            return self();
        }

        public B headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
            this.headersCustomizer = Objects.requireNonNull(customizer, "headersCustomizer cannot be null");
            return self();
        }

        public B sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
            this.sessionManagementCustomizer = Objects.requireNonNull(customizer, "sessionManagementCustomizer cannot be null");
            return self();
        }

        public B logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
            this.logoutCustomizer = Objects.requireNonNull(customizer, "logoutCustomizer cannot be null");
            return self();
        }

        public B authorizeStaticPermitAll(List<String> patterns) {
            this.staticMatchers = List.copyOf(Objects.requireNonNull(patterns, "patterns cannot be null"));
            return self();
        }
        public B authorizeStaticPermitAll(String... patterns) {
            this.staticMatchers = List.of(Objects.requireNonNull(patterns, "patterns cannot be null"));
            return self();
        }

        public B rawHttp(SafeHttpCustomizer<HttpSecurity> customizer) {
            this.rawHttpCustomizers.add(Objects.requireNonNull(customizer, "rawHttp customizer cannot be null"));
            return self();
        }

        public abstract O build();
    }
}