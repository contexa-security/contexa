package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.bootstrap.configurer.SecurityConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.*;
import java.util.stream.Collectors;

/**
 * SecurityConfigurer 들의 초기화(init) 및 구성(configure) 생명주기를 관리하고 실행합니다.
 * 플랫폼의 보안 설정을 최종적으로 HttpSecurity 객체들에 적용하는 역할을 합니다.
 */
@Slf4j
public final class SecurityConfigurerOrchestrator {

    private final SecurityConfigurerProvider configurerProvider;

    public SecurityConfigurerOrchestrator(SecurityConfigurerProvider configurerProvider) {
        this.configurerProvider = Objects.requireNonNull(configurerProvider, "SecurityConfigurerProvider cannot be null");
    }

    public void applyConfigurations(
            List<FlowContext> flows,
            PlatformContext platformContext,
            PlatformConfig platformConfig) throws Exception {

        Objects.requireNonNull(flows, "Flows list cannot be null");
        Objects.requireNonNull(platformContext, "PlatformContext cannot be null");
        Objects.requireNonNull(platformConfig, "PlatformConfig cannot be null");

        log.info("SecurityConfigurerOrchestrator: Starting to apply configurations for {} flows.", flows.size());

        // 1. 모든 "전역" SecurityConfigurer의 init() 호출 (애플리케이션 시작 시 1회)
        List<SecurityConfigurer> globalConfigurers = configurerProvider.getGlobalConfigurers(platformContext, platformConfig);
        if (globalConfigurers == null) {
            globalConfigurers = Collections.emptyList();
        }
        log.debug("SecurityConfigurerOrchestrator: Initializing {} global configurers.", globalConfigurers.size());
        for (SecurityConfigurer cfg : globalConfigurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .toList()) {
            try {
                log.trace("  Initializing global configurer: {}", cfg.getClass().getSimpleName());
                cfg.init(platformContext, platformConfig);
            } catch (Exception e) {
                String errorMsg = "Error during global SecurityConfigurer initialization: " + cfg.getClass().getSimpleName();
                log.error(errorMsg, e);
                throw new RuntimeException(errorMsg, e);
            }
        }

        // 2. 각 FlowContext (즉, 각 HttpSecurity 인스턴스) 별로 Configurer 구성 적용
        for (FlowContext fc : flows) {
            Objects.requireNonNull(fc, "FlowContext in list cannot be null");
            HttpSecurity currentHttpSecurity = Objects.requireNonNull(fc.http(), "HttpSecurity in FlowContext cannot be null");
            String flowTypeName = Objects.requireNonNull(fc.flow(), "AuthenticationFlowConfig in FlowContext cannot be null").getTypeName();

            log.debug("SecurityConfigurerOrchestrator: Applying configurations for flow: {} (HttpSecurity hash: {})",
                    flowTypeName, currentHttpSecurity.hashCode());
            // 현재 처리 중인 FlowContext를 플랫폼 컨텍스트에 공유 (일부 Configurer가 접근할 수 있도록)
            platformContext.share(FlowContext.class, fc);

            // 현재 Flow에 특화된 Configurer 가져오기 (주로 Feature Adapter들)
            List<SecurityConfigurer> flowSpecificAdapters = configurerProvider.getFlowSpecificConfigurers(
                    platformContext, platformConfig, currentHttpSecurity
            );
            if (flowSpecificAdapters == null) {
                flowSpecificAdapters = Collections.emptyList();
            }

            // 최종적으로 이 Flow에 적용될 Configurer 목록: 전역 Configurer + 플로우 특화 어댑터
            // 전역 Configurer 들의 configure()도 각 Flow의 HttpSecurity에 대해 호출되어야 함 (예: AsepConfigurer)
            List<SecurityConfigurer> finalConfigurersForFlow = new ArrayList<>();
            finalConfigurersForFlow.addAll(globalConfigurers); // 모든 전역 Configurer를 먼저 추가
            finalConfigurersForFlow.addAll(flowSpecificAdapters); // 그 다음 플로우 특화 어댑터 추가

            // 중복 제거 (동일 인스턴스 기준) 및 순서대로 정렬
            finalConfigurersForFlow = finalConfigurersForFlow.stream()
                    .distinct()
                    .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                    .collect(Collectors.toList());

            log.debug("  Configuring flow {} with {} final configurers: {}",
                    flowTypeName, finalConfigurersForFlow.size(),
                    finalConfigurersForFlow.stream().map(cfg -> cfg.getClass().getSimpleName() + "(order:" + cfg.getOrder() + ")").collect(Collectors.joining(", ")));

            for (SecurityConfigurer cfg : finalConfigurersForFlow) {
                try {
                    log.trace("    Configuring flow {} with configurer: {}", flowTypeName, cfg.getClass().getSimpleName());
                    cfg.configure(fc);
                } catch (Exception e) {
                    String errorMessage = String.format(
                            "Error applying SecurityConfigurer '%s' for flow '%s'.",
                            cfg.getClass().getSimpleName(), flowTypeName
                    );
                    log.error(errorMessage, e);
                    throw new RuntimeException(errorMessage, e);
                }
            }
            log.info("  Successfully applied all configurers for flow: {}", flowTypeName);
        }
        log.info("SecurityConfigurerOrchestrator: All configurations applied successfully for {} flows.", flows.size());
    }
}
