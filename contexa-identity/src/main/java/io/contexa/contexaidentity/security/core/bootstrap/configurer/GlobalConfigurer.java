package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 플랫폼 전역 HTTP 보안 설정을 적용합니다.
 * (ASEP 관련 로직은 AsepConfigurer로 분리되었습니다.)
 */
@Slf4j
public class GlobalConfigurer implements SecurityConfigurer {
    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        // System.out.println("GlobalConfigurer ctx = " + ctx.http(ctx.flowContext().flow()) + ", config = " + config);
        // 플랫폼 전역 초기화 로직 (ASEP와 무관)
        log.info("GlobalConfigurer initialized by Platform.");
    }

    @Override
    public void configure(FlowContext ctx) {
        // 플랫폼 전역 HttpSecurity 커스터마이징 로직 (ASEP와 무관)
        SafeHttpCustomizer<HttpSecurity> customizer = ctx.config().getGlobalCustomizer();
        if (customizer == null) {
            log.debug("No global customizer found for flow: {}", ctx.flow().getTypeName());
            return;
        }
        try {
            log.debug("Applying platform's global customizer for flow: {}", ctx.flow().getTypeName());
            customizer.customize(ctx.http());
        } catch (Exception ex) {
            log.warn("Platform's global customizer failed for flow: {}", ctx.flow().getTypeName(), ex);
        }
    }

    @Override
    public int getOrder() {
        // 예를 들어, 매우 높은 우선순위(낮은 숫자)로 다른 설정보다 먼저 적용되도록
        return SecurityConfigurer.HIGHEST_PRECEDENCE + 100; // 플랫폼에 정의된 상수 사용 (가정)
        // 또는 return 0; 등
    }
}

