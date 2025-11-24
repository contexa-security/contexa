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

    // P1.2: 스레드 안전성을 위한 ReadWriteLock
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    public MfaUrlMatcher(AuthUrlProvider authUrlProvider,
                         ApplicationContext applicationContext) {
        this.authUrlProvider = authUrlProvider;
        this.applicationContext = applicationContext;
        this.matcherMap = new HashMap<>();
        this.configuredUrls = new HashSet<>();
        // ⭐ Phase 3: 생성자에서 초기화하지 않음
        // SecurityPlatformInitializer가 Factor Options를 AuthUrlProvider에 주입한 후
        // MfaContinuationFilter.initializeUrlMatchers()를 통해 초기화됨
    }

    /**
     * URL Matcher 동적 초기화
     *
     * <p>
     * AuthUrlProvider에 Factor Options가 주입된 후 호출되어야 합니다.
     * 이 메서드는 MfaAuthenticationAdapter.apply() 내에서
     * MfaContinuationFilter.initializeUrlMatchers()를 통해 호출됩니다.
     * </p>
     */
    public void initializeMatchers() {
        // P1.2: Write Lock으로 초기화 보호
        lock.writeLock().lock();
        try {
            // 기존 매처 제거
            matcherMap.clear();
            configuredUrls.clear();

            log.info("🔄 Initializing MfaUrlMatcher with updated AuthUrlProvider URLs...");

            // 팩터 선택 (GET: 페이지 요청, POST: 선택 처리)
            addMatcher(MfaRequestType.FACTOR_SELECTION,
                    authUrlProvider.getMfaSelectFactor(), "GET");
            addMatcher(MfaRequestType.FACTOR_SELECTION,
                    authUrlProvider.getMfaSelectFactor(), "POST");

            // OTT 코드 요청 (생성 및 이메일 전송)
            addMatcher(MfaRequestType.OTT_CODE_REQUEST,
                    authUrlProvider.getOttCodeGeneration(), "POST");

            // OTT 코드 검증
            addMatcher(MfaRequestType.OTT_CODE_VERIFY,
                    authUrlProvider.getOttLoginProcessing(), "POST");

            // Passkey 챌린지 시작 (INITIATE_CHALLENGE 이벤트 발송)
            addMatcher(MfaRequestType.CHALLENGE_INITIATION,
                    authUrlProvider.getPasskeyChallengeUi(), "POST");

            // Passkey 검증 처리
            addMatcher(MfaRequestType.LOGIN_PROCESSING,
                    authUrlProvider.getPasskeyLoginProcessing(), "POST");

            // MFA 취소
            addMatcher(MfaRequestType.CANCEL_MFA,
                    authUrlProvider.getMfaCancel(), "POST");

            log.info("✅ MfaUrlMatcher initialized: {} request types, {} URLs configured",
                matcherMap.size(), configuredUrls.size());
            log.debug("Configured URLs: {}", configuredUrls);
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
            log.debug("Added matcher for type {}: {} [{}]", type, pattern, method);
        }
    }

    public boolean isMfaRequest(HttpServletRequest request) {
        // P1.2: Read Lock으로 읽기 보호
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
        // P1.2: Read Lock으로 읽기 보호
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
        // P1.2: Read Lock으로 읽기 보호
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