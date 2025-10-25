package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.bootstrap.configurer.AuthConfigurerAdapter;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.SecurityConfigurer;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.StateConfigurerAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * SecurityConfigurer 인스턴스 목록을 제공하는 기본 구현체입니다.
 * Spring 컨텍스트에서 SecurityConfigurer 빈들을 수집하고,
 * FeatureRegistry를 통해 동적으로 Feature 관련 ConfigurerAdapter들을 추가합니다.
 */
@Component
@Slf4j
public final class DefaultSecurityConfigurerProvider implements SecurityConfigurerProvider {

    private final List<SecurityConfigurer> collectedBaseConfigurers;
    private final AdapterRegistry adapterRegistry;

    @Autowired
    public DefaultSecurityConfigurerProvider(
            List<SecurityConfigurer> baseConfigurers, // Spring 컨텍스트에서 모든 SecurityConfigurer 빈 주입
            AdapterRegistry adapterRegistry,
            ApplicationContext applicationContext) {
        this.collectedBaseConfigurers = (baseConfigurers != null) ? new ArrayList<>(baseConfigurers) : new ArrayList<>();
        this.adapterRegistry = Objects.requireNonNull(adapterRegistry, "FeatureRegistry cannot be null");
        log.info("DefaultSecurityConfigurerProvider initialized with {} base configurers.", this.collectedBaseConfigurers.size());
        if (log.isDebugEnabled()) {
            this.collectedBaseConfigurers.forEach(cfg -> log.debug("  - Detected Base Configurer: {}", cfg.getClass().getName()));
        }
    }

    @Override
    public List<SecurityConfigurer> getGlobalConfigurers(PlatformContext platformContext, PlatformConfig platformConfig) {
        // 애플리케이션 컨텍스트에서 주입된 모든 SecurityConfigurer 빈들을 "전역" Configurer로 간주하여 반환합니다.
        // 이들은 플랫폼 초기화 시점에 init()이 호출되고, 각 플로우 설정 시점에 configure()가 호출됩니다.
        // AsepConfigurer, GlobalConfigurer, FlowConfigurer 등이 여기에 포함됩니다.
        log.debug("DefaultSecurityConfigurerProvider: Providing {} base/global configurers.", collectedBaseConfigurers.size());
        return List.copyOf(this.collectedBaseConfigurers);
    }

    @Override
    public List<SecurityConfigurer> getFlowSpecificConfigurers(
            PlatformContext platformContext,
            PlatformConfig platformConfig,
            HttpSecurity httpForScope) {
        Objects.requireNonNull(httpForScope, "HttpSecurity (httpForScope) cannot be null for getFlowSpecificConfigurers");

        List<SecurityConfigurer> flowSpecificAdapters = new ArrayList<>();
        AuthenticationFlowConfig currentFlow = httpForScope.getSharedObject(AuthenticationFlowConfig.class);

        if (currentFlow == null) {
            log.warn("DefaultSecurityConfigurerProvider: AuthenticationFlowConfig not found in HttpSecurity sharedObjects for hash {}. " +
                            "Cannot determine flow-specific features. No feature adapters will be added for this scope.",
                    httpForScope.hashCode());
            return Collections.emptyList(); // 이 HttpSecurity에 매핑된 플로우 정보가 없으면, 특화된 어댑터는 없음
        }

        log.debug("DefaultSecurityConfigurerProvider: Determining flow-specific configurer adapters for flow '{}' (HttpSecurity hash: {})",
                currentFlow.getTypeName(), httpForScope.hashCode());

        // 현재 Flow에 정의된 인증 단계(AuthFeature) 및 상태 관리(StateFeature)에 대한 어댑터만 추가
        if (adapterRegistry != null) {
            // 현재 플로우 하나만 포함하는 리스트를 전달하여 해당 플로우에 필요한 Feature만 가져오도록 함
            List<AuthenticationFlowConfig> singleFlowList = Collections.singletonList(currentFlow);

            adapterRegistry.getAuthAdaptersFor(singleFlowList)
                    .forEach(authAdapter -> {
                        flowSpecificAdapters.add(new AuthConfigurerAdapter(authAdapter));
                        log.debug("  Added AuthFeatureConfigurerAdapter for authAdapter '{}' relevant to flow '{}'.",
                                authAdapter.getId(), currentFlow.getTypeName());
                    });

            adapterRegistry.getStateAdaptersFor(singleFlowList)
                    .forEach(stateAdapter -> {
                        flowSpecificAdapters.add(new StateConfigurerAdapter(stateAdapter, platformContext));
                        log.debug("  Added StateFeatureConfigurerAdapter for state feature '{}' relevant to flow '{}'.",
                                stateAdapter.getId(), currentFlow.getTypeName());
                    });
        } else {
            log.warn("DefaultSecurityConfigurerProvider: FeatureRegistry is null. Cannot add feature-based adapters for flow '{}'.", currentFlow.getTypeName());
        }

        log.debug("DefaultSecurityConfigurerProvider: Providing {} flow-specific configurer adapters for flow '{}'.",
                flowSpecificAdapters.size(), currentFlow.getTypeName());
        return List.copyOf(flowSpecificAdapters);
    }
}
