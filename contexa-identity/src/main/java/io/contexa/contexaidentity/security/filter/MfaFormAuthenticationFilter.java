package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.infra.session.SessionIdGenerationException;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

@Slf4j
public class MfaFormAuthenticationFilter extends BaseAuthenticationFilter {

    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;

    private final BytesKeyGenerator sessionIdGenerator;
    private final SecureRandom secureRandom;

    private static final int MAX_SESSION_ID_GENERATION_ATTEMPTS = 5;
    private static final int MAX_COLLISION_RESOLUTION_ATTEMPTS = 3;

    private String usernameParameter = "username";
    private String passwordParameter = "password";

    public MfaFormAuthenticationFilter(AuthenticationManager authenticationManager,
                                       ApplicationContext applicationContext,
                                       AuthContextProperties properties,
                                       RequestMatcher requestMatcher) {
        super(requestMatcher, authenticationManager, properties);

        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(properties, "properties cannot be null");

        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);
        this.sessionRepository = applicationContext.getBean(MfaSessionRepository.class);

        this.sessionIdGenerator = KeyGenerators.secureRandom(32);
        this.secureRandom = new SecureRandom();

    }

    @Override
    protected Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        String username = request.getParameter(usernameParameter);
        String password = request.getParameter(passwordParameter);

        if (username == null) {
            username = "";
        }
        if (password == null) {
            password = "";
        }

        username = username.trim();

        UsernamePasswordAuthenticationToken authRequest =
                UsernamePasswordAuthenticationToken.unauthenticated(username, password);

        return authenticationManager.authenticate(authRequest);
    }

    @Override
    public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                         Authentication authentication) throws IOException, ServletException {

        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        cleanupExistingSession(request, response);

        String mfaSessionId = generateSecureDistributedSessionId(request);
        String flowTypeNameForContext = AuthType.MFA.name().toLowerCase();

        FactorContext factorContext = new FactorContext(
                mfaSessionId,
                authentication,
                MfaState.NONE,
                flowTypeNameForContext
        );

        enhanceFactorContextWithSecurityInfo(factorContext, request);

        try {
            stateMachineIntegrator.initializeStateMachine(factorContext, request, response);
            MfaState actualState = stateMachineIntegrator.getCurrentState(factorContext.getMfaSessionId());
            if (actualState != factorContext.getCurrentState()) {
                log.warn("State mismatch! FactorContext: {}, StateMachine: {} for session: {}",
                        factorContext.getCurrentState(), actualState, factorContext.getMfaSessionId());
            }
            successHandler.onAuthenticationSuccess(request, response, authentication);

        } catch (Exception e) {
            log.error("Failed to initialize unified State Machine for Form MFA session: {}", mfaSessionId, e);

            cleanupFailedSession(mfaSessionId, request, response);
            unsuccessfulAuthentication(request, response, new AuthenticationException("State Machine initialization failed", e) {
            });
        }
    }

    private String generateSecureDistributedSessionId(HttpServletRequest request) {
        if (sessionRepository.supportsDistributedSync()) {
            return generateDistributedUniqueSessionId(request);
        } else {
            return generateSecureSessionId();
        }
    }

    private String generateDistributedUniqueSessionId(HttpServletRequest request) {

        for (int attempt = 0; attempt < MAX_SESSION_ID_GENERATION_ATTEMPTS; attempt++) {
            try {
                String baseId = generateSecureSessionId();
                return sessionRepository.generateUniqueSessionId(baseId, request);

            } catch (SessionIdGenerationException e) {
                log.warn("Session ID generation failed (attempt: {}): {}", attempt + 1, e.getMessage());

                if (attempt == MAX_SESSION_ID_GENERATION_ATTEMPTS - 1) {
                    return resolveSessionIdGenerationFailure(request);
                }

                try {
                    Thread.sleep(50L * (1L << Math.min(attempt, 4)));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Session ID generation interrupted", ie);
                }
            }
        }

        log.warn("All distributed session ID generation attempts failed, using fallback method");
        return generateSecureSessionId();
    }

    private String resolveSessionIdGenerationFailure(HttpServletRequest request) {

        try {
            String originalId = generateSecureSessionId();
            return sessionRepository.resolveSessionIdCollision(originalId, request, MAX_COLLISION_RESOLUTION_ATTEMPTS);
        } catch (Exception e) {
            log.error("Failed to resolve session ID collision", e);
            return generateSecureSessionId();
        }
    }

    private void enhanceFactorContextWithSecurityInfo(FactorContext factorContext, HttpServletRequest request) {
        String deviceId = getOrCreateDeviceId(request);
        factorContext.setAttribute(FactorContextAttributes.DeviceAndSession.DEVICE_ID, deviceId);
        factorContext.setAttribute(FactorContextAttributes.DeviceAndSession.CLIENT_IP,
                getClientIpAddress(request));
        factorContext.setAttribute(FactorContextAttributes.DeviceAndSession.USER_AGENT,
                request.getHeader("User-Agent"));
        factorContext.setAttribute(FactorContextAttributes.Timestamps.LOGIN_TIMESTAMP,
                System.currentTimeMillis());

    }

    private void cleanupFailedSession(String mfaSessionId, HttpServletRequest request, HttpServletResponse response) {
        try {
            if (sessionRepository.existsSession(mfaSessionId)) {
                sessionRepository.removeSession(mfaSessionId, request, response);
            }
        } catch (Exception e) {
            log.warn("Failed to cleanup failed session: {}", mfaSessionId, e);
        }
    }

    @Override
    public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationException failed) throws IOException, ServletException {
        securityContextHolderStrategy.clearContext();
        stateMachineIntegrator.cleanupSession(request, response);

        log.warn("Form MFA authentication failed from IP: {} using repository: {}. Error: {}",
                getClientIpAddress(request),
                sessionRepository.getRepositoryType(),
                failed.getMessage());

        failureHandler.onAuthenticationFailure(request, response, failed);
    }

    private void cleanupExistingSession(HttpServletRequest request, HttpServletResponse response) {
        try {
            stateMachineIntegrator.cleanupSession(request, response);
        } catch (Exception e) {
            log.warn("Failed to cleanup existing session using {}: {}", sessionRepository.getRepositoryType(), e.getMessage());
        }
    }

    private String generateSecureSessionId() {
        byte[] bytes = sessionIdGenerator.generateKey();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String getOrCreateDeviceId(HttpServletRequest request) {
        String deviceId = request.getHeader("X-Device-Id");
        if (StringUtils.hasText(deviceId) && isValidDeviceId(deviceId)) {
            return deviceId;
        }

        if (sessionRepository.supportsDistributedSync()) {
            deviceId = generateDistributedDeviceId(request);
        } else {
            deviceId = generateSecureDeviceId();
        }

        return deviceId;
    }

    private String generateDistributedDeviceId(HttpServletRequest request) {
        String clientInfo = getClientIpAddress(request) + "|" +
                (request.getHeader("User-Agent") != null ? request.getHeader("User-Agent") : "") + "|" +
                System.currentTimeMillis();

        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(clientInfo.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            log.warn("Failed to generate distributed device ID, using fallback", e);
            return generateSecureDeviceId();
        }
    }

    private boolean isValidDeviceId(String deviceId) {
        return deviceId.matches("^[a-zA-Z0-9_-]{22,}$") ||
                deviceId.matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    }

    private String generateSecureDeviceId() {
        byte[] bytes = new byte[24];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public void setUsernameParameter(String usernameParameter) {
        Assert.hasText(usernameParameter, "usernameParameter cannot be empty");
        this.usernameParameter = usernameParameter;
    }

    public void setPasswordParameter(String passwordParameter) {
        Assert.hasText(passwordParameter, "passwordParameter cannot be empty");
        this.passwordParameter = passwordParameter;
    }
}
