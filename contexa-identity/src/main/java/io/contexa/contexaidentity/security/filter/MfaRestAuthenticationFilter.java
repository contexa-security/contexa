package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.infra.session.SessionIdGenerationException;
import io.contexa.contexaidentity.domain.LoginRequest;
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
public class MfaRestAuthenticationFilter extends BaseAuthenticationFilter {

    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;

    
    private final BytesKeyGenerator sessionIdGenerator;
    private final SecureRandom secureRandom;
    private final long authDelay;

    
    private static final int MAX_SESSION_ID_GENERATION_ATTEMPTS = 5;
    private static final int MAX_COLLISION_RESOLUTION_ATTEMPTS = 3;

    public MfaRestAuthenticationFilter(AuthenticationManager authenticationManager,
                                       ApplicationContext applicationContext,
                                       AuthContextProperties properties,
                                       RequestMatcher requestMatcher) {
        super(requestMatcher, authenticationManager, properties);

        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(properties, "mfaSettings cannot be null");

        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);
        this.sessionRepository = applicationContext.getBean(MfaSessionRepository.class);

        
        this.sessionIdGenerator = KeyGenerators.secureRandom(32);
        this.secureRandom = new SecureRandom();
        this.authDelay = properties.getMfa().getMinimumDelayMs();

        log.info("RestAuthenticationFilter initialized with {} repository. Distributed sync: {}",
                sessionRepository.getRepositoryType(), sessionRepository.supportsDistributedSync());
    }

    
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

            log.info("State Machine initialized. FactorContext state: {} for user: {} (session: {})",
                    factorContext.getCurrentState(),
                    factorContext.getUsername(),
                    factorContext.getMfaSessionId());

            MfaState actualState = stateMachineIntegrator.getCurrentState(factorContext.getMfaSessionId());
            if (actualState != factorContext.getCurrentState()) {
                log.warn("State mismatch! FactorContext: {}, StateMachine: {} for session: {}",
                        factorContext.getCurrentState(), actualState, factorContext.getMfaSessionId());
            }

            successHandler.onAuthenticationSuccess(request, response, authentication);

        } catch (Exception e) {
            log.error("Failed to initialize unified State Machine for session: {}", mfaSessionId, e);

            
            cleanupFailedSession(mfaSessionId, request, response);

            unsuccessfulAuthentication(request, response,
                    new AuthenticationException("State Machine initialization failed", e) {});
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
        log.debug("Generating distributed unique session ID using repository: {}", sessionRepository.getRepositoryType());

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
        log.info("Attempting to resolve session ID generation failure using collision resolution");

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

        log.debug("Enhanced FactorContext with security info: deviceId={}, repository={}",
                deviceId, sessionRepository.getRepositoryType());
    }

    
    private void cleanupFailedSession(String mfaSessionId, HttpServletRequest request, HttpServletResponse response) {
        try {
            if (sessionRepository.existsSession(mfaSessionId)) {
                sessionRepository.removeSession(mfaSessionId, request, response);
                log.debug("Cleaned up failed session: {}", mfaSessionId);
            }
        } catch (Exception e) {
            log.warn("Failed to cleanup failed session: {}", mfaSessionId, e);
        }
    }

    
    public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException failed) throws IOException, ServletException {
        securityContextHolderStrategy.clearContext();
        stateMachineIntegrator.cleanupSession(request, response);

        log.warn("Authentication failed for user: {} from IP: {} using repository: {}",
                failed.getAuthenticationRequest() != null ?
                        failed.getAuthenticationRequest().getName() : "unknown",
                getClientIpAddress(request),
                sessionRepository.getRepositoryType());

        failureHandler.onAuthenticationFailure(request, response, failed);
    }

    
    private void cleanupExistingSession(HttpServletRequest request, HttpServletResponse response) {
        try {
            stateMachineIntegrator.cleanupSession(request, response);
            log.debug("Existing session cleaned up using repository pattern: {}", sessionRepository.getRepositoryType());
        } catch (Exception e) {
            log.warn("Failed to cleanup existing session using {}: {}", sessionRepository.getRepositoryType(), e.getMessage());
        }
    }

    

    public void ensureMinimumDelay(long startTime) {
        long elapsed = System.currentTimeMillis() - startTime;
        if (elapsed < authDelay) {
            try {
                Thread.sleep(authDelay - elapsed);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public void validateLoginRequest(LoginRequest login) {
        if (!StringUtils.hasText(login.username()) || !StringUtils.hasText(login.password())) {
            throw new IllegalArgumentException("Username and password must not be empty");
        }

        if (login.username().length() > 100) {
            throw new IllegalArgumentException("Username too long");
        }

        if (login.password().length() > 200) {
            throw new IllegalArgumentException("Password too long");
        }
    }

    private String generateSecureSessionId() {
        byte[] bytes = sessionIdGenerator.generateKey();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public String getClientIpAddress(HttpServletRequest request) {
        String[] headers = {
                "X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR", "HTTP_X_FORWARDED", "HTTP_X_CLUSTER_CLIENT_IP",
                "HTTP_CLIENT_IP", "HTTP_FORWARDED_FOR", "HTTP_FORWARDED", "HTTP_VIA", "REMOTE_ADDR"
        };

        for (String header : headers) {
            String ip = request.getHeader(header);
            if (ip != null && ip.length() != 0 && !"unknown".equalsIgnoreCase(ip)) {
                return ip.split(",")[0].trim();
            }
        }

        return request.getRemoteAddr();
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

        log.debug("Generated deviceId: {} using repository: {}", deviceId, sessionRepository.getRepositoryType());
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
}
