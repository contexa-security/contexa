package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.adapter.AuthenticationAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.validator.DslValidatorService;
import io.contexa.contexaidentity.security.exception.DslConfigurationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;

import java.util.List;

/**
 * Auto-bootstrap for security platform:
 * SecurityConfig 에서 정의된 PlatformConfig와 FeatureProvider가
 * 이 클래스에서 SecurityPlatform에 전달되어 초기화됩니다.
 */
@Slf4j
@RequiredArgsConstructor
public class PlatformBootstrap implements InitializingBean {

    private final SecurityPlatform platform;
    private final PlatformConfig config;
    private final AdapterRegistry registry;
    private final DslValidatorService dslValidatorService;

    @Override
    public void afterPropertiesSet() throws Exception {
        log.info("PlatformBootstrap: Starting DSL configuration validation...");

        // 1. 플랫폼 전역 준비
        List<AuthenticationFlowConfig> flows = config.getFlows();
        List<AuthenticationAdapter> features = registry.getAuthAdaptersFor(flows);
        platform.prepareGlobal(config, features);

        // 2. 플랫폼 초기화
        platform.initialize();

        // 3. 플랫폼 오류 검증
        try {
            dslValidatorService.validate(config, "PlatformSecurityConfig.java (DSL)");

        } catch (DslConfigurationException e) {
            log.error("DSL 유효성 검사 실패로 서버 기동을 중단합니다.", e);
            throw e;
        }
        log.info("PlatformBootstrap: DSL configuration validation passed.");

        log.info("PlatformBootstrap: Security platform initialized successfully.");
    }
}
