package io.contexa.contexaidentity.security.core.context;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.security.core.bootstrap.AdapterRegistry;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

public class FlowContextFactory {

    private static final Logger log = LoggerFactory.getLogger(FlowContextFactory.class);
    private final AdapterRegistry adapterRegistry;
    private final ApplicationContext applicationContext; // 추가

    public FlowContextFactory(AdapterRegistry adapterRegistry, ApplicationContext applicationContext) {
        this.adapterRegistry = Objects.requireNonNull(adapterRegistry, "featureRegistry cannot be null");
        this.applicationContext = Objects.requireNonNull(applicationContext, "applicationContext cannot be null");
    }

    public List<FlowContext> createAndSortFlows(PlatformConfig config, PlatformContext platformContext) {
        List<FlowContext> flows = new ArrayList<>();
        if (config == null || CollectionUtils.isEmpty(config.getFlows())) {
            log.warn("PlatformConfig or its flows are null/empty. No FlowContexts will be created.");
            return flows;
        }

        for (AuthenticationFlowConfig flowCfg : config.getFlows()) {
            // HttpSecurity 인스턴스를 PlatformContext를 통해 새로 생성
            HttpSecurity http = platformContext.newHttp();
            // 생성된 HttpSecurity를 현재 FlowConfig와 함께 PlatformContext에 등록 (매핑)
            platformContext.registerHttp(flowCfg, http);

            // FlowContext를 생성하기 전에, 현재 처리중인 flowCfg를 HttpSecurity의 공유 객체로 먼저 설정.
            // 이는 MfaAuthenticationFeature.apply 등에서 현재 FlowConfig 정보에 접근해야 할 때 사용됨.
            http.setSharedObject(AuthenticationFlowConfig.class, flowCfg);
            // PlatformContext 자체도 HttpSecurity에 공유 (AbstractAuthenticationFeature 등에서 ApplicationContext 접근용)
            http.setSharedObject(PlatformContext.class, platformContext);
            FlowContext fc = new FlowContext(flowCfg, http, platformContext, config);
            setupSharedObjectsForFlow(fc); // HttpSecurity에 필요한 공유 객체들 설정
            flows.add(fc);
        }
        flows.sort(Comparator.comparingInt(f -> f.flow().getOrder()));
        log.info("{} FlowContext(s) created and sorted.", flows.size());
        return flows;
    }

    private void setupSharedObjectsForFlow(io.contexa.contexaidentity.security.core.context.FlowContext fc) {
        HttpSecurity http = fc.http();
        AuthenticationFlowConfig flowConfig = fc.flow();
        ApplicationContext appContext = this.applicationContext; // 직접 주입받은 것 사용

        log.debug("Setting up shared objects for flow: {}", flowConfig.getTypeName());

        boolean isMfaFlow = "mfa".equalsIgnoreCase(flowConfig.getTypeName());
        if (isMfaFlow) {
            log.debug("MFA flow detected for '{}', setting up MFA shared objects.", flowConfig.getTypeName());
            // P1-2 버그 수정: DSL에서 설정한 MfaPolicyProvider 우선 사용
            setSharedObjectIfAbsent(http, MfaPolicyProvider.class, () -> {
                // 1. DSL 설정에서 가져오기 (flowConfig.getMfaPolicyProvider())
                MfaPolicyProvider dslProvider = flowConfig.getMfaPolicyProvider();
                if (dslProvider != null) {
                    log.debug("Using MfaPolicyProvider from DSL configuration for flow '{}'", flowConfig.getTypeName());
                    return dslProvider;
                }
                // 2. Fallback: ApplicationContext Bean
                log.debug("Using MfaPolicyProvider from ApplicationContext for flow '{}'", flowConfig.getTypeName());
                return appContext.getBean(MfaPolicyProvider.class);
            });
            setSharedObjectIfAbsent(http, ObjectMapper.class, ObjectMapper::new);
        }
    }
    private <T> void setSharedObjectIfAbsent(HttpSecurity http, Class<T> type, Supplier<T> supplier) {
        if (http.getSharedObject(type) == null) {
            try {
                T object = supplier.get();
                if (object != null) {
                    http.setSharedObject(type, object);
                }
            } catch (Exception e) {
                log.warn("Failed to create/set shared object of type {} for current flow: {}", type.getSimpleName(), e.getMessage());
            }
        }
    }
}