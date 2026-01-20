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
                        
                        
                        
                        
                        HttpMethod httpMethod = HttpMethod.POST;
                        

                        UrlInfo currentUrlInfoKey = new UrlInfo(loginProcessingUrl, httpMethod, flow, step);
                        String usageContext = currentUrlInfoKey.getContext();

                        urlUsageMap.computeIfAbsent(currentUrlInfoKey, k -> new ArrayList<>()).add(usageContext);
                    }
                }
            }
        }

        

        return result;
    }
}
