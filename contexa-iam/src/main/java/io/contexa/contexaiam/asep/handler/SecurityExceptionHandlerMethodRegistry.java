package io.contexa.contexaiam.asep.handler;

import io.contexa.contexaiam.asep.annotation.SecurityControllerAdvice;
import io.contexa.contexaiam.asep.annotation.SecurityExceptionHandler;
import io.contexa.contexaiam.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.MethodIntrospector;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ReflectionUtils.MethodFilter;
import org.springframework.web.accept.ContentNegotiationManager;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.ServletWebRequest;

import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class SecurityExceptionHandlerMethodRegistry implements ApplicationContextAware, InitializingBean {

    private ApplicationContext applicationContext;
    private final Map<Class<?>, ExceptionHandlerMethodResolver> methodResolverCache = new ConcurrentHashMap<>(64);
    private final Map<Object, ExceptionHandlerMethodResolver> adviceToResolverCache = new LinkedHashMap<>();
    private ContentNegotiationManager contentNegotiationManager;

    public SecurityExceptionHandlerMethodRegistry() {
        this.contentNegotiationManager = new ContentNegotiationManager(new HeaderContentNegotiationStrategy());
    }

    public void setContentNegotiationManager(ContentNegotiationManager contentNegotiationManager) {
        this.contentNegotiationManager = Objects.requireNonNull(contentNegotiationManager, "ContentNegotiationManager must not be null");
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(applicationContext, "ApplicationContext must not be set for SecurityExceptionHandlerMethodRegistry");
        initializeExceptionHandlerAdviceCache();
    }

    private void initializeExceptionHandlerAdviceCache() {
        if (this.applicationContext == null) {
            log.warn("ASEP: ApplicationContext is null. Cannot initialize SecurityExceptionHandlerAdviceCache.");
            return;
        }
        log.debug("ASEP: Initializing SecurityExceptionHandlerAdviceCache: Looking for @SecurityControllerAdvice beans...");

        List<Object> adviceBeans = new ArrayList<>(this.applicationContext.getBeansWithAnnotation(SecurityControllerAdvice.class).values());
        AnnotationAwareOrderComparator.sort(adviceBeans);

        for (Object adviceBean : adviceBeans) {
            Class<?> beanType = ClassUtils.getUserClass(adviceBean);
            ExceptionHandlerMethodResolver resolver = this.methodResolverCache.computeIfAbsent(beanType, ExceptionHandlerMethodResolver::new);
            if (resolver.hasExceptionMappings()) { // ExceptionHandlerMethodResolver에 hasExceptionMappings()가 이미 있음
                this.adviceToResolverCache.put(adviceBean, resolver);
                log.debug("ASEP: Detected @SecurityExceptionHandler methods in advice bean: {}", beanType.getName());
            }
        }
        log.info("ASEP: Initialized SecurityExceptionHandlerAdviceCache with {} advice beans.", this.adviceToResolverCache.size());
    }

    /**
     * 등록된 예외 처리 메서드 매핑이 하나라도 있는지 확인합니다.
     * @return 매핑이 있으면 true, 없으면 false
     */
    public boolean hasAnyMappings() { // <<-- 추가된 메서드
        return !this.adviceToResolverCache.isEmpty();
    }

    @Nullable
    public HandlerMethod findBestExceptionHandlerMethod(
            Throwable exception,
            @Nullable Authentication authentication,
            HttpServletRequest servletRequest) {

        Assert.notNull(exception, "Exception must not be null");
        Assert.notNull(servletRequest, "HttpServletRequest must not be null");

        NativeWebRequest webRequest = new ServletWebRequest(servletRequest);
        List<MediaType> acceptedMediaTypes;
        try {
            acceptedMediaTypes = this.contentNegotiationManager.resolveMediaTypes(webRequest);
            if (CollectionUtils.isEmpty(acceptedMediaTypes) ||
                    (acceptedMediaTypes.size() == 1 && MediaType.ALL.equals(acceptedMediaTypes.get(0)))) {
                acceptedMediaTypes = Collections.singletonList(MediaType.APPLICATION_JSON); // 기본값을 JSON으로 명시
                log.trace("ASEP: No specific Accept header, defaulting to application/json for exception handling.");
            }
        } catch (Exception ex) {
            log.warn("ASEP: Could not resolve media types for request due to {}. Using default [application/json].", ex.getMessage());
            acceptedMediaTypes = Collections.singletonList(MediaType.APPLICATION_JSON);
        }


        for (Map.Entry<Object, ExceptionHandlerMethodResolver> entry : this.adviceToResolverCache.entrySet()) {
            Object adviceBean = entry.getKey();
            ExceptionHandlerMethodResolver resolver = entry.getValue();

            for (MediaType acceptedMediaType : acceptedMediaTypes) {
                Method bestMatchingMethod = resolver.resolveMethod(exception, acceptedMediaType);
                if (bestMatchingMethod != null) {
                    SecurityExceptionHandler ann = AnnotatedElementUtils.findMergedAnnotation(bestMatchingMethod, SecurityExceptionHandler.class);
                    String[] produces = (ann != null) ? ann.produces() : new String[0];
                    int priority = (ann != null) ? ann.priority() : Ordered.LOWEST_PRECEDENCE;
                    Class<? extends Throwable>[] handledExceptions = (ann != null && ann.value().length > 0) ?
                            ann.value() :
                            new Class[]{findClosestExceptionTypeFromMethodParams(bestMatchingMethod, exception.getClass())};

                    log.debug("ASEP: Found best matching handler method [{}] in bean [{}] for exception [{}] and accepted media type [{}]. Produces: {}, Priority: {}",
                            bestMatchingMethod.getName(), adviceBean.getClass().getSimpleName(),
                            exception.getClass().getSimpleName(), acceptedMediaType, Arrays.toString(produces), priority);
                    return new HandlerMethod(adviceBean, bestMatchingMethod, handledExceptions, priority, produces);
                }
            }
        }

        log.debug("ASEP: No suitable @SecurityExceptionHandler method found in any @SecurityControllerAdvice beans for exception [{}] and accepted media types {}.",
                exception.getClass().getName(), acceptedMediaTypes);
        return null;
    }

    private Class<? extends Throwable> findClosestExceptionTypeFromMethodParams(Method method, Class<? extends Throwable> actualExceptionType) {
        for (Class<?> paramType : method.getParameterTypes()) {
            if (Throwable.class.isAssignableFrom(paramType) && paramType.isAssignableFrom(actualExceptionType)) {
                return (Class<? extends Throwable>) paramType;
            }
        }
        return Throwable.class;
    }

    private static class ExceptionHandlerMethodResolver {
        private static final MethodFilter EXCEPTION_HANDLER_METHODS = method ->
                AnnotatedElementUtils.hasAnnotation(method, SecurityExceptionHandler.class);

        private final Map<Method, ExceptionHandlerMappingInfo> methodMappings = new LinkedHashMap<>();

        public ExceptionHandlerMethodResolver(Class<?> handlerType) {
            for (Method method : MethodIntrospector.selectMethods(handlerType, EXCEPTION_HANDLER_METHODS)) {
                SecurityExceptionHandler ann = AnnotatedElementUtils.findMergedAnnotation(method, SecurityExceptionHandler.class);
                if (ann == null) continue;

                Class<? extends Throwable>[] exceptionTypes = ann.value();
                if (exceptionTypes.length == 0) {
                    exceptionTypes = detectExceptionMappingsFromMethodParams(method);
                }
                if (exceptionTypes.length == 0) {
                    exceptionTypes = new Class[]{Throwable.class};
                    log.warn("ASEP: No exception types mapped to @SecurityExceptionHandler method {} by annotation or parameter. Defaulting to handle Throwable.class with priority {}.", method.toGenericString(), ann.priority());
                }

                ExceptionHandlerMappingInfo mappingInfo = new ExceptionHandlerMappingInfo(
                        Set.of(exceptionTypes),
                        parseProducesMediaTypes(ann.produces(), method),
                        method,
                        ann.priority()
                );
                this.methodMappings.put(method, mappingInfo); // 같은 메소드에 대해 덮어쓰기 가능 (보통은 메소드별로 고유)
            }
        }

        private Set<MediaType> parseProducesMediaTypes(String[] produces, Method method) {
            if (produces == null || produces.length == 0) {
                return Collections.emptySet();
            }
            Set<MediaType> mediaTypes = new LinkedHashSet<>();
            for (String mediaTypeStr : produces) {
                try {
                    mediaTypes.add(MediaType.parseMediaType(mediaTypeStr));
                } catch (Exception e) {
                    log.warn("ASEP: Invalid media type '{}' declared on @SecurityExceptionHandler for method {}. It will be ignored.",
                            mediaTypeStr, method.toGenericString(), e);
                }
            }
            return Collections.unmodifiableSet(mediaTypes);
        }

        private Class<? extends Throwable>[] detectExceptionMappingsFromMethodParams(Method method) {
            List<Class<? extends Throwable>> types = new ArrayList<>();
            for (Class<?> paramType : method.getParameterTypes()) {
                if (Throwable.class.isAssignableFrom(paramType)) {
                    types.add((Class<? extends Throwable>) paramType);
                }
            }
            return types.toArray(new Class[0]);
        }

        public boolean hasExceptionMappings() {
            return !this.methodMappings.isEmpty();
        }

        @Nullable
        public Method resolveMethod(Throwable exception, MediaType acceptedMediaType) {
            Class<? extends Throwable> exceptionType = exception.getClass();
            List<ExceptionHandlerMappingInfo> candidates = new ArrayList<>();

            for (ExceptionHandlerMappingInfo mappingInfo : this.methodMappings.values()) {
                for (Class<? extends Throwable> mappedExType : mappingInfo.exceptionTypes()) {
                    if (mappedExType.isAssignableFrom(exceptionType)) {
                        candidates.add(mappingInfo);
                        break;
                    }
                }
            }

            if (candidates.isEmpty()) {
                Throwable cause = exception.getCause();
                if (cause != null) {
                    return resolveMethod(cause, acceptedMediaType);
                }
                return null;
            }

            candidates.sort(new ExceptionHandlerMappingInfoComparator(exceptionType));

            for (ExceptionHandlerMappingInfo mappingInfo : candidates) {
                if (mappingInfo.matches(acceptedMediaType)) {
                    return mappingInfo.handlerMethod();
                }
            }
            // Content Negotiation에 맞는 것이 없을 경우, produces가 없는 (모든 타입을 허용하는) 가장 우선순위 높은 핸들러를 고려
            // 또는, acceptedMediaType이 와일드카드일 경우 첫번째 후보 반환 등
            // 현재 로직은 produces가 명시적으로 매칭되거나, produces가 아예 없는 경우를 찾지 않음.
            // -> 수정: produces가 없거나 MediaType.ALL을 포함하는 경우도 고려
            for (ExceptionHandlerMappingInfo mappingInfo : candidates) {
                if (mappingInfo.producibleMediaTypes().isEmpty() ||
                        mappingInfo.producibleMediaTypes().stream().anyMatch(mt -> acceptedMediaType.isCompatibleWith(mt) || mt.isCompatibleWith(MediaType.ALL))) {
                    return mappingInfo.handlerMethod();
                }
            }


            return null;
        }

        private record ExceptionHandlerMappingInfo(
                Set<Class<? extends Throwable>> exceptionTypes,
                Set<MediaType> producibleMediaTypes,
                Method handlerMethod,
                int priority
        ) {
            public boolean matches(MediaType acceptedMediaType) {
                if (this.producibleMediaTypes.isEmpty()) {
                    return true; // produces 명시 안하면 모든 타입 수용
                }
                for (MediaType producible : this.producibleMediaTypes) {
                    if (acceptedMediaType.isCompatibleWith(producible)) {
                        return true;
                    }
                }
                return false;
            }
        }

        private static class ExceptionHandlerMappingInfoComparator implements Comparator<ExceptionHandlerMappingInfo> {
            private final Class<? extends Throwable> exceptionType;

            public ExceptionHandlerMappingInfoComparator(Class<? extends Throwable> exceptionType) {
                this.exceptionType = exceptionType;
            }

            @Override
            public int compare(ExceptionHandlerMappingInfo o1, ExceptionHandlerMappingInfo o2) {
                int depth1 = getDepth(o1.exceptionTypes(), this.exceptionType);
                int depth2 = getDepth(o2.exceptionTypes(), this.exceptionType);
                if (depth1 != depth2) {
                    return Integer.compare(depth1, depth2); // 더 구체적인 예외 (낮은 깊이) 우선
                }
                return Integer.compare(o1.priority(), o2.priority()); // 우선순위 (낮은 값) 우선
            }

            private int getDepth(Set<Class<? extends Throwable>> mappedTypes, Class<?> targetExceptionType) {
                int minDepth = Integer.MAX_VALUE;
                for (Class<? extends Throwable> mappedType : mappedTypes) {
                    if (mappedType.isAssignableFrom(targetExceptionType)) {
                        int depth = 0;
                        Class<?> current = targetExceptionType;
                        while (current != null && !current.equals(mappedType)) {
                            current = current.getSuperclass();
                            depth++;
                        }
                        if (current != null) { // mappedType에 도달함
                            minDepth = Math.min(minDepth, depth);
                        }
                    }
                }
                return minDepth;
            }
        }
    }
}
