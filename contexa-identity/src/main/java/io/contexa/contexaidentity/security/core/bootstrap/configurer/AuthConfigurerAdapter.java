package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.adapter.AuthenticationAdapter;
import io.contexa.contexaidentity.security.core.adapter.auth.MfaAuthenticationAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexacommon.enums.AuthType;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Objects;

/**
 * AuthenticationAdapter를 SecurityConfigurer로 감싸는 어댑터
 */
@Slf4j
public class AuthConfigurerAdapter implements SecurityConfigurer {
    private final AuthenticationAdapter adapter;

    /**
     * @param adapter 인증 기능 구현체
     */
    public AuthConfigurerAdapter(AuthenticationAdapter adapter) {
        this.adapter = Objects.requireNonNull(adapter, "AuthenticationAdapter cannot be null"); // Null 체크 추가
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {}

    /**
     * flow의 stepConfigs 에서 이 adapter에 해당하는 Step만 적용
     */
    @Override
    public void configure(FlowContext fc) throws Exception {
        Objects.requireNonNull(fc, "FlowContext cannot be null"); // Null 체크 추가
        Objects.requireNonNull(fc.flow(), "FlowContext.flow cannot be null"); // Null 체크 추가
        Objects.requireNonNull(fc.http(), "FlowContext.http cannot be null"); // Null 체크 추가
        // fc.flow().stateConfig()는 null일 수 있으므로, adapter.apply 호출 전에 Null 체크 또는 기본값 처리 필요

        List<AuthenticationStepConfig> steps = fc.flow().getStepConfigs();

        // 1. MfaAuthenticationAdapter 경우 특별 처리
        if (adapter instanceof MfaAuthenticationAdapter) {
            // MfaAuthenticationAdapter 전체 MFA 흐름을 구성하므로,
            // 특정 step.type()과 매칭되지 않아도 모든 stepConfigs를 전달하여 적용될 수 있음.
            // 또는, flowConfig.typeName()이 "mfa"일 때만 적용하도록 조건 추가 가능.
            if (AuthType.MFA.name().equalsIgnoreCase(fc.flow().getTypeName())) {
                log.debug("Applying MfaAuthenticationAdapter for flow: {}", fc.flow().getTypeName());
                adapter.apply(fc.http(), steps, fc.flow().getStateConfig());

                return; 
            }
        }

        // 2. 일반 AuthenticationAdapter 처리
        if (steps.isEmpty()) { // steps가 null일 수도 있으므로 체크
            log.trace("No steps configured for flow: {}, adapter: {}", fc.flow().getTypeName(), adapter.getId());
            return;
        }

        boolean applied = false; // adapter가 한 번만 적용되도록 플래그 사용
        for (AuthenticationStepConfig step : steps) {
            if (step != null && adapter.getId().equalsIgnoreCase(step.getType())) {
                // 해당 adapter에 대해 첫 번째 매칭되는 step 에서만 apply 호출
                log.info("Applying adapter: {} for step type: {} in flow: {}", adapter.getId(), step.getType(), fc.flow().getTypeName());
                // AuthenticationAdapter.apply는 해당 adapter와 관련된 모든 steps 설정을 사용할 수 있도록 전체 steps를 전달
                adapter.apply(fc.http(), steps, fc.flow().getStateConfig());
                applied = true; // 이 adapter에 대한 적용이 완료되었음을 표시
                // 일반적으로 하나의 AuthenticationAdapter는 하나의 SecurityFilterChain에서 한 번만 주요 설정을 담당.
                // 만약 동일 타입의 step이 여러 개 있고 각기 다르게 설정되어야 한다면,
                // AuthenticationAdapter.apply 메소드가 이를 구분해서 처리할 수 있어야 함.
                // 여기서는 adapter 당 한 번의 apply 호출을 가정.
                break; // 이 adapter에 대한 적용을 마쳤으므로 루프 종료
            }
        }
        if (!applied) {
            log.info("adapter: {} was not applicable to any step in flow: {}", adapter.getId(), fc.flow().getTypeName());
        }
    }

    @Override
    public int getOrder() {
        // adapter 자체에 order가 있다면 그 값을 따르도록 수정 가능
        // return adapter.getOrder();
        return 300; // 현재는 고정값
    }
}
