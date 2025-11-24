package io.contexa.contexaiam.resource.scanner;

import io.contexa.contexacommon.entity.ManagedResource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class MvcResourceScanner implements ResourceScanner {

    private final ApplicationContext applicationContext;

    @Value("${app.docs.rest-docs-path:/docs/index.html}")
    private String restDocsPath;

    @Override
    public List<ManagedResource> scan() {
        Map<String, RequestMappingHandlerMapping> beansOfType = applicationContext.getBeansOfType(RequestMappingHandlerMapping.class);
        RequestMappingHandlerMapping handlerMapping = beansOfType.get("requestMappingHandlerMapping");
        final List<ManagedResource> resources = new ArrayList<>();
        final Map<RequestMappingInfo, HandlerMethod> handlerMethods = handlerMapping.getHandlerMethods();

        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry : handlerMethods.entrySet()) {
            final RequestMappingInfo mappingInfo = entry.getKey();
            final HandlerMethod handlerMethod = entry.getValue();
            final Class<?> beanType = handlerMethod.getBeanType();

            if (!beanType.getPackageName().startsWith("io.contexa.contexaiam")) continue;
            if (!beanType.isAnnotationPresent(Controller.class) && !beanType.isAnnotationPresent(RestController.class)) continue;

            PathPatternsRequestCondition pathPatternsCondition = mappingInfo.getPathPatternsCondition();
            if (pathPatternsCondition == null || pathPatternsCondition.getPatterns().isEmpty()) continue;

            final String urlPattern = pathPatternsCondition.getPatterns().stream().findFirst().get().getPatternString();
            final String httpMethodStr = mappingInfo.getMethodsCondition().getMethods().stream()
                    .findFirst().map(Enum::name).orElse("ANY");

            ManagedResource.HttpMethod httpMethod;
            try {
                httpMethod = ManagedResource.HttpMethod.valueOf(httpMethodStr.toUpperCase());
            } catch (IllegalArgumentException e) {
                httpMethod = ManagedResource.HttpMethod.ANY;
            }

            // [변경] @Operation 대신 메서드 이름과 기본 설명 사용
            String friendlyName = handlerMethod.getMethod().getName();
            String description = String.format("URL: [%s] %s", httpMethodStr, urlPattern);

            // [신규] Spring REST Docs 문서의 앵커 링크 생성 규칙
            // 예: /docs/index.html#users_create
            String docsAnchor = String.format("%s_%s", beanType.getSimpleName().toLowerCase().replace("controller", ""), handlerMethod.getMethod().getName().toLowerCase());
            String apiDocsUrl = String.format("%s#%s", restDocsPath, docsAnchor);

            resources.add(ManagedResource.builder()
                    .resourceIdentifier(urlPattern)
                    .httpMethod(httpMethod)
                    .resourceType(ManagedResource.ResourceType.URL)
                    .friendlyName(friendlyName)
                    .description(description)
                    .serviceOwner(beanType.getSimpleName())
                    .apiDocsUrl(apiDocsUrl)
                    .status(ManagedResource.Status.NEEDS_DEFINITION)
                    .build());
        }

        log.info("Successfully scanned and discovered {} URL resources for REST Docs.", resources.size());
        return resources;
    }
}