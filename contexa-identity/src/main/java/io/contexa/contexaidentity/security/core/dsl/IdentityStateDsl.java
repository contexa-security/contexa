package io.contexa.contexaidentity.security.core.dsl;

import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateConfigurer;
import io.contexa.contexaidentity.security.core.adapter.state.session.SessionStateConfigurer;
import org.springframework.security.config.Customizer;

/**
 * 인증 방식 설정 후 호출되는 DSL로,
 * 인증 후 사용할 상태 관리 전략을 선택하는 단계입니다.
 */
public interface IdentityStateDsl {

    /**
     * 세션 기반 상태 유지 전략을 사용합니다.
     * @param customizer SessionStateConfigurer를 커스터마이징합니다.
     * @return 상위 DSL (IdentityAuthDsl) 으로 복귀하여 추가 인증 방식 또는 빌드 가능
     */
    IdentityAuthDsl session(Customizer<SessionStateConfigurer> customizer);

    /**
     * Spring AuthorizationServer/ResourceServer(OAuth2) 기반 JWT/Opaque Token 전략을 사용합니다.
     * @param customizer OAuth2StateConfigurer를 커스터마イ징합니다.
     * @return 상위 DSL (IdentityAuthDsl) 으로 복귀
     */
    IdentityAuthDsl oauth2(Customizer<OAuth2StateConfigurer> customizer);
}

