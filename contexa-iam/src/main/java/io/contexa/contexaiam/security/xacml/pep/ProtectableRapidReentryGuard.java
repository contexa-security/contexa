package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexacore.autonomous.execution.RapidProtectableReentryDeniedException;
import io.contexa.contexacore.autonomous.repository.ProtectableRapidReentryRepository;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;

@Slf4j
public class ProtectableRapidReentryGuard {

    private static final long DEFAULT_WINDOW_SECONDS = 5L;
    private static final Duration DEFAULT_WINDOW = Duration.ofSeconds(DEFAULT_WINDOW_SECONDS);

    private final ProtectableRapidReentryRepository repository;
    private final Duration window;

    public ProtectableRapidReentryGuard(ProtectableRapidReentryRepository repository) {
        this(repository, DEFAULT_WINDOW);
    }

    public ProtectableRapidReentryGuard(ProtectableRapidReentryRepository repository, Duration window) {
        this.repository = repository;
        this.window = window == null ? DEFAULT_WINDOW : window;
    }

    public void check(Authentication authentication, MethodInvocation methodInvocation) {
        if (!tryAcquire(authentication, methodInvocation)) {
            String resourceKey = resolveResourceKey(methodInvocation);
            log.error("[ProtectableRapidReentryGuard] Rapid protected re-entry denied: userId={}, resource={}",
                    authentication != null ? authentication.getName() : null,
                    resourceKey);
            throw new RapidProtectableReentryDeniedException(resourceKey, Math.max(0L, window.toSeconds()));
        }
    }

    public boolean tryAcquire(Authentication authentication, MethodInvocation methodInvocation) {
        if (window.isZero() || window.isNegative()) {
            return true;
        }

        if (authentication == null || !authentication.isAuthenticated()) {
            return true;
        }

        HttpServletRequest request = resolveCurrentRequest();
        if (request == null) {
            return true;
        }

        String userId = authentication.getName();
        if (userId == null || userId.isBlank()) {
            return true;
        }

        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
        if (contextBindingHash == null || contextBindingHash.isBlank()) {
            return true;
        }

        String resourceKey = buildResourceKey(methodInvocation, request);
        return repository.tryAcquire(userId, contextBindingHash, resourceKey, window);
    }

    private HttpServletRequest resolveCurrentRequest() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            return attrs != null ? attrs.getRequest() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private String resolveResourceKey(MethodInvocation methodInvocation) {
        HttpServletRequest request = resolveCurrentRequest();
        if (request == null) {
            return methodInvocation.getMethod().getDeclaringClass().getSimpleName()
                    + "."
                    + methodInvocation.getMethod().getName();
        }
        return buildResourceKey(methodInvocation, request);
    }

    private String buildResourceKey(MethodInvocation methodInvocation, HttpServletRequest request) {
        String methodKey = methodInvocation.getMethod().getDeclaringClass().getSimpleName()
                + "."
                + methodInvocation.getMethod().getName();
        Object[] args = methodInvocation.getArguments();
        if (args.length > 0 && args[0] != null) {
            methodKey += "[" + args[0].hashCode() + "]";
        }
        String requestKey = request.getMethod() + " " + request.getRequestURI();
        return methodKey + "|" + requestKey;
    }
}
