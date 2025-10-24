package io.contexa.contexaidentity.security.core.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.security.identification.UserIdentificationService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.asep.annotation.EnableAsep;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.handler.MfaFactorProcessingSuccessHandler;
import io.contexa.contexaidentity.security.handler.PrimaryAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.handler.UnifiedAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import io.contexa.contexaidentity.security.utils.writer.JsonAuthResponseWriter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
@RequiredArgsConstructor
@EnableAsep
public class MfaInfrastructureAutoConfiguration {

    private final AuthContextProperties authContextProperties;
    private final TokenService tokenService;

    @Bean
    @ConditionalOnMissingBean
    public PrimaryAuthenticationSuccessHandler unifiedAuthenticationSuccessHandler(AuthResponseWriter authResponseWriter,
                                                                                   MfaPolicyProvider mfaPolicyProvider,
                                                                                   ApplicationContext applicationContext,
                                                                                   MfaStateMachineIntegrator MfaStateMachineIntegrator,
                                                                                   MfaSessionRepository mfaSessionRepository) {
        return new PrimaryAuthenticationSuccessHandler(mfaPolicyProvider, tokenService,authResponseWriter,
                                                        authContextProperties, applicationContext, MfaStateMachineIntegrator, mfaSessionRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public UnifiedAuthenticationFailureHandler unifiedAuthenticationFailureHandler(MfaStateMachineIntegrator mfaStateMachineIntegrator,
                                                                                    MfaPolicyProvider mfaPolicyProvider,
                                                                                    AuthResponseWriter authResponseWriter,
                                                                                    MfaSessionRepository mfaSessionRepository,
                                                                                    UserIdentificationService userIdentificationService) {
        return new UnifiedAuthenticationFailureHandler(mfaStateMachineIntegrator, mfaPolicyProvider, authResponseWriter, authContextProperties,mfaSessionRepository, userIdentificationService);
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaFactorProcessingSuccessHandler mfaFactorProcessingSuccessHandler(MfaStateMachineIntegrator mfaStateMachineIntegrator,
                                                                               MfaPolicyProvider mfaPolicyProvider,
                                                                               AuthResponseWriter authResponseWriter,
                                                                               ApplicationContext applicationContext,
                                                                               MfaSessionRepository mfaSessionRepository) {
        return new MfaFactorProcessingSuccessHandler(mfaStateMachineIntegrator, mfaPolicyProvider, authResponseWriter,
                applicationContext, authContextProperties, mfaSessionRepository,tokenService);
    }


    @Bean
    @ConditionalOnMissingBean
    public AuthResponseWriter authResponseWriter(ObjectMapper objectMapper) {
        return new JsonAuthResponseWriter(objectMapper);
    }
}
