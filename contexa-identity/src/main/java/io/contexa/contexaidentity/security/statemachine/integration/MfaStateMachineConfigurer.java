package io.contexa.contexaidentity.security.statemachine.integration;

import io.contexa.contexaidentity.security.core.bootstrap.configurer.SecurityConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * MFA State Machine을 Security 설정에 통합하는 Configurer
 */
@Slf4j
@RequiredArgsConstructor
public class MfaStateMachineConfigurer implements SecurityConfigurer {

    private final MfaStateMachineService stateMachineService;

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        log.info("Initializing MFA State Machine Configurer");
        // 전역 초기화 로직
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (!AuthType.MFA.name().equalsIgnoreCase(fc.flow().getTypeName())) {
            // MFA 플로우가 아니면 스킵
            return;
        }

        log.info("Configuring MFA State Machine for flow: {}", fc.flow().getTypeName());

        HttpSecurity http = fc.http();

        // State Machine 서비스를 SharedObject로 등록
        http.setSharedObject(MfaStateMachineService.class, stateMachineService);

        // 추가 설정이 필요한 경우 여기에 구현
    }

    @Override
    public int getOrder() {
        // State Machine 설정은 다른 보안 설정 이후에 적용
        return 600;
    }
}