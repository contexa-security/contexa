package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;

import java.util.*;

@Slf4j
public class LoginProcessingUrlUniquenessValidator implements Validator<List<AuthenticationFlowConfig>> {

    private static class UrlInfo {
        final String url;
        final HttpMethod method;
        final String flowId;
        final String stepType;
        final int stepOrder;

        UrlInfo(String url, HttpMethod method, AuthenticationFlowConfig flow, AuthenticationStepConfig step) {
            this.url = url;
            this.method = method;
            this.flowId = flow.getTypeName() + "@" + flow.getOrder();
            this.stepType = step.getType();
            this.stepOrder = step.getOrder();
        }

        String getContext() {
            return String.format("Flow '%s', Step '%s'(order:%d)", flowId, stepType, stepOrder);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            UrlInfo that = (UrlInfo) o;
            return Objects.equals(url, that.url) && method == that.method;
        }

        @Override
        public int hashCode() {
            return Objects.hash(url, method);
        }

        @Override
        public String toString() {
            return method + " " + url;
        }
    }

    @Override
    public ValidationResult validate(List<AuthenticationFlowConfig> flows) {
        ValidationResult result = new ValidationResult();
        if (flows == null || flows.isEmpty()) {
            return result;
        }

        Map<UrlInfo, List<String>> urlUsageMap = new HashMap<>();

        for (AuthenticationFlowConfig flow : flows) {

            for (AuthenticationStepConfig step : flow.getStepConfigs()) {
                Object optionsObject = step.getOptions().get("_options");
                if (optionsObject instanceof AuthenticationProcessingOptions processingOptions) {
                    String loginProcessingUrl = processingOptions.getLoginProcessingUrl();

                    if (loginProcessingUrl != null) {
                        // 대부분의 인증 필터는 POST를 기본으로 사용.
                        // TODO: 각 Options 타입에 따라 예상되는 HTTP 메서드를 더 정확히 파악하는 로직 필요.
                        //       예를 들어, OAuth2 콜백은 GET일 수 있음.
                        //       지금은 모든 loginProcessingUrl이 POST라고 가정.
                        HttpMethod httpMethod = HttpMethod.POST;
                        // if (processingOptions instanceof SomeGetBasedOptions) httpMethod = HttpMethod.GET;

                        UrlInfo currentUrlInfoKey = new UrlInfo(loginProcessingUrl, httpMethod, flow, step);
                        String usageContext = currentUrlInfoKey.getContext();

                        urlUsageMap.computeIfAbsent(currentUrlInfoKey, k -> new ArrayList<>()).add(usageContext);
                    }
                }
            }
        }

        /*urlUsageMap.forEach((urlInfo, contexts) -> {
            if (contexts.size() > 1) {
                String contextsString = String.join(", ", contexts);
                result.addError(String.format("치명적 오류: 동일한 인증 처리 경로 및 HTTP 메서드 ('%s')가 여러 곳에서 사용되었습니다. [%s]", urlInfo.toString(), contextsString));
                log.error("DSL VALIDATION ERROR: Duplicate loginProcessingUrl and method: '{}' is used by: {}", urlInfo.toString(), contextsString);
            }
        });*/

        return result;
    }
}
