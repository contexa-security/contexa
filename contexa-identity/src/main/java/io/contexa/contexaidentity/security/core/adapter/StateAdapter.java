package io.contexa.contexaidentity.security.core.adapter;

import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 인증 후 상태 관리 전략(세션 기반, 외부 JWT 라이브러리 기반, OAuth2/JWT 인증 서버 등)을
 * HttpSecurity에 적용하는 기능 인터페이스입니다.
 *
 * 각 구현체는 자신의 전략에 맞추어 세션 정책, 토큰 필터, 공유 객체 설정 등을 구성합니다.
 */
public interface StateAdapter {

    /**
     * 이 상태 기능의 고유 식별자(ID)를 반환합니다.
     * 보통 DSL에서 지정한 상태 전략 이름("session", "jwt", "oauth2")과 매핑됩니다.
     *
     * @return 상태 기능 ID
     */
    String getId();

    /**
     * 주어진 HttpSecurity 및 PlatformContext를 사용하여
     * 세션 생성 정책, JWT/토큰 필터, 공유 객체 등록 등을 적용합니다.
     *
     * @param http  HttpSecurity 빌더
     * @param ctx   PlatformContext (공유 객체 접근, 체인 등록 지원 등)
     * @throws Exception 구성 중 오류 발생 시
     */
    void apply(HttpSecurity http, PlatformContext ctx) throws Exception;
}

