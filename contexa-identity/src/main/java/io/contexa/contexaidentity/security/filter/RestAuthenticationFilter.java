package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.domain.dto.UserDto;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;
import java.util.UUID;

@Slf4j
public class RestAuthenticationFilter extends BaseAuthenticationFilter {

    private final MfaSessionRepository sessionRepository;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    public RestAuthenticationFilter(RequestMatcher requestMatcher,
                                    AuthenticationManager authenticationManager,
                                    AuthContextProperties properties,
                                    MfaSessionRepository sessionRepository,
                                    MfaStateMachineIntegrator stateMachineIntegrator) {
        super(requestMatcher, authenticationManager, properties);
        this.sessionRepository = sessionRepository;
        this.stateMachineIntegrator = stateMachineIntegrator;
        log.info("RestAuthenticationFilter initialized for single-factor authentication with MFA session support");
    }
    /**
     * 인증 성공 처리 - MFA 세션 초기화 포함
     *
     * 단일 인증 플로우에서도 MFA 정책 평가를 위해 MFA 세션을 초기화합니다.
     * 이를 통해 PrimaryAuthenticationSuccessHandler가 일관되게 동작할 수 있습니다.
     */
    public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                          Authentication authentication) throws IOException, ServletException {

        // 1. MFA 세션 초기화 (MfaRestAuthenticationFilter와 동일한 패턴)
        String baseId = UUID.randomUUID().toString();
        String mfaSessionId = sessionRepository.generateUniqueSessionId(baseId, request);

        log.debug("Initializing MFA session for single-factor authentication. Session: {}, User: {}",
                  mfaSessionId, ((UserDto) authentication.getPrincipal()).getUsername());

        // 2. FactorContext 생성
        FactorContext factorContext = new FactorContext(
                mfaSessionId,
                authentication,
                MfaState.PRIMARY_AUTHENTICATION_COMPLETED,
                AuthType.REST.name()
        );

        // 3. State Machine 초기화 및 세션 저장
        stateMachineIntegrator.initializeStateMachine(factorContext, request, response);

        log.info("MFA session initialized for single-factor authentication. Session: {}, User: {}",
                 mfaSessionId, ((UserDto) authentication.getPrincipal()).getUsername());

        // 4. Security Context 설정
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        // 5. Success Handler 호출 (이제 MFA 세션이 준비됨)
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }


    /**
     * 인증 실패 처리
     */
    public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException failed) throws IOException, ServletException {
        securityContextHolderStrategy.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
