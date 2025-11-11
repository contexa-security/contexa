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