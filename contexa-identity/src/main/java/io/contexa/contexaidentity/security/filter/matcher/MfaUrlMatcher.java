package io.contexa.contexaidentity.security.filter.matcher;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@Slf4j
@Getter
public class MfaUrlMatcher {

    private final AuthUrlProvider authUrlProvider;
    private final ApplicationContext applicationContext;
    private final Map<MfaRequestType, List<RequestMatcher>> matcherMap;
    private final Set<String> configuredUrls;

    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    public MfaUrlMatcher(AuthUrlProvider authUrlProvider,
                         ApplicationContext applicationContext) {
        this.authUrlProvider = authUrlProvider;
        this.applicationContext = applicationContext;
        this.matcherMap = new HashMap<>();
        this.configuredUrls = new HashSet<>();

    }

    public void initializeMatchers() {
        
        lock.writeLock().lock();
        try {
            
            matcherMap.clear();
            configuredUrls.clear();

            addMatcher(MfaRequestType.FACTOR_SELECTION,
                    authUrlProvider.getMfaSelectFactor(), "GET");
            addMatcher(MfaRequestType.FACTOR_SELECTION,
                    authUrlProvider.getMfaSelectFactor(), "POST");

            addMatcher(MfaRequestType.OTT_CODE_REQUEST,
                    authUrlProvider.getOttCodeGeneration(), "POST");

            addMatcher(MfaRequestType.OTT_CODE_VERIFY,
                    authUrlProvider.getOttLoginProcessing(), "POST");

            addMatcher(MfaRequestType.CHALLENGE_INITIATION,
                    authUrlProvider.getPasskeyChallengeUi(), "POST");

            addMatcher(MfaRequestType.LOGIN_PROCESSING,
                    authUrlProvider.getPasskeyLoginProcessing(), "POST");

            addMatcher(MfaRequestType.CANCEL_MFA,
                    authUrlProvider.getMfaCancel(), "POST");

                                } finally {
            lock.writeLock().unlock();
        }
    }

    private void addMatcher(MfaRequestType type, String pattern, String method) {
        if (pattern != null && !pattern.isEmpty()) {
            HttpMethod httpMethod = method != null ? HttpMethod.valueOf(method.toUpperCase()) : HttpMethod.POST;
            RequestMatcher matcher = PathPatternRequestMatcher.withDefaults().matcher(httpMethod, pattern);

            matcherMap.computeIfAbsent(type, k -> new ArrayList<>()).add(matcher);
            configuredUrls.add(pattern + " [" + method + "]");
                    }
    }

    public boolean isMfaRequest(HttpServletRequest request) {
        
        lock.readLock().lock();
        try {
            return matcherMap.values().stream()
                    .flatMap(List::stream)
                    .anyMatch(matcher -> matcher.matches(request));
        } finally {
            lock.readLock().unlock();
        }
    }

    public MfaRequestType getRequestType(HttpServletRequest request) {
        
        lock.readLock().lock();
        try {
            for (Map.Entry<MfaRequestType, List<RequestMatcher>> entry : matcherMap.entrySet()) {
                for (RequestMatcher matcher : entry.getValue()) {
                    if (matcher.matches(request)) {
                        return entry.getKey();
                    }
                }
            }
            return MfaRequestType.UNKNOWN;
        } finally {
            lock.readLock().unlock();
        }
    }

    public RequestMatcher createRequestMatcher() {
        
        lock.readLock().lock();
        try {
            List<RequestMatcher> allMatchers = new ArrayList<>();
            matcherMap.values().forEach(allMatchers::addAll);
            return new OrRequestMatcher(allMatchers);
        } finally {
            lock.readLock().unlock();
        }
    }
}