package io.contexa.contexaidentity.security.core.dsl;

import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateConfigurer;
import io.contexa.contexaidentity.security.core.adapter.state.session.SessionStateConfigurer;
import org.springframework.security.config.Customizer;

public interface IdentityStateDsl {

    IdentityAuthDsl session(Customizer<SessionStateConfigurer> customizer);

    IdentityAuthDsl oauth2(Customizer<OAuth2StateConfigurer> customizer);
}

