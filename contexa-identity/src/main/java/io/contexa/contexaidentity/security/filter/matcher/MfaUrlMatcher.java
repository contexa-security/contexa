package io.contexa.contexaidentity.security.filter.matcher;

import io.contexa.contexaidentity.security.properties.AuthContextProperties;
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

@Slf4j
@Getter
public class MfaUrlMatcher {

    private final AuthUrlProvider authUrlProvider;
    private final ApplicationContext applicationContext;
    private final Map<MfaRequestType, List<RequestMatcher>> matcherMap;
    private final Set<String> configuredUrls;

    public MfaUrlMatcher(AuthUrlProvider authUrlProvider,
                         ApplicationContext applicationContext) {
        this.authUrlProvider = authUrlProvider;
        this.applicationContext = applicationContext;
        this.matcherMap = new HashMap<>();
        this.configuredUrls = new HashSet<>();
        initializeMatchers();
    }

    private void initializeMatchers() {
        // MFA 시작
        addMatcher(MfaRequestType.MFA_INITIATE,
                authUrlProvider.getMfaInitiate(), "GET");

        // 팩터 선택
        addMatcher(MfaRequestType.SELECT_FACTOR,
                authUrlProvider.getMfaSelectFactor(), "GET");

        // OTT 토큰 생성
        addMatcher(MfaRequestType.TOKEN_GENERATION,
                authUrlProvider.getOttCodeGeneration(), "POST");

        // OTT 로그인 처리
        addMatcher(MfaRequestType.LOGIN_PROCESSING,
                authUrlProvider.getOttLoginProcessing(), "POST");

        // Passkey 로그인 처리
        addMatcher(MfaRequestType.LOGIN_PROCESSING,
                authUrlProvider.getPasskeyLoginProcessing(), "POST");
    }

    private void addMatcher(MfaRequestType type, String pattern, String method) {
        if (pattern != null && !pattern.isEmpty()) {
            RequestMatcher matcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, pattern);

            matcherMap.computeIfAbsent(type, k -> new ArrayList<>()).add(matcher);
            configuredUrls.add(pattern + " [" + method + "]");
            log.debug("Added matcher for type {}: {} [{}]", type, pattern, method);
        }
    }

    public boolean isMfaRequest(HttpServletRequest request) {
        return matcherMap.values().stream()
                .flatMap(List::stream)
                .anyMatch(matcher -> matcher.matches(request));
    }

    public MfaRequestType getRequestType(HttpServletRequest request) {
        for (Map.Entry<MfaRequestType, List<RequestMatcher>> entry : matcherMap.entrySet()) {
            for (RequestMatcher matcher : entry.getValue()) {
                if (matcher.matches(request)) {
                    return entry.getKey();
                }
            }
        }
        return MfaRequestType.UNKNOWN;
    }

    public RequestMatcher createRequestMatcher() {
        List<RequestMatcher> allMatchers = new ArrayList<>();
        matcherMap.values().forEach(allMatchers::addAll);
        return new OrRequestMatcher(allMatchers);
    }
}