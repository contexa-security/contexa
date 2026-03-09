package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexacore.autonomous.exception.RapidProtectableReentryDeniedException;
import io.contexa.contexacore.autonomous.repository.ProtectableRapidReentryRepository;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;

@Slf4j
@RequiredArgsConstructor
public class ProtectableRapidReentryGuard {

    private static final long WINDOW_SECONDS = 5L;
    private static final Duration WINDOW = Duration.ofSeconds(WINDOW_SECONDS);

    private final ProtectableRapidReentryRepository repository;

    public void check(Authentication authentication, MethodInvocation methodInvocation) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return;
        }

        HttpServletRequest request = resolveCurrentRequest();
        if (request == null) {
            return;
        }

        String userId = authentication.getName();
        if (userId == null || userId.isBlank()) {
            return;
        }

        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
        if (contextBindingHash == null || contextBindingHash.isBlank()) {
            return;
        }

        String resourceKey = buildResourceKey(methodInvocation, request);
        boolean acquired = repository.tryAcquire(userId, contextBindingHash, resourceKey, WINDOW);
        if (!acquired) {
            log.error("[ProtectableRapidReentryGuard] Rapid protected re-entry denied: userId={}, resource={}",
                    userId, resourceKey);
            throw new RapidProtectableReentryDeniedException(resourceKey, WINDOW_SECONDS);
        }
    }

    private HttpServletRequest resolveCurrentRequest() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            return attrs != null ? attrs.getRequest() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private String buildResourceKey(MethodInvocation methodInvocation, HttpServletRequest request) {
        String methodKey = methodInvocation.getMethod().getDeclaringClass().getSimpleName()
                + "."
                + methodInvocation.getMethod().getName();
        String requestKey = request.getMethod() + " " + request.getRequestURI();
        return methodKey + "|" + requestKey;
    }
}
