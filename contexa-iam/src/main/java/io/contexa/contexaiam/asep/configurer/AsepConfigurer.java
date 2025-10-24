package io.contexa.contexaiam.asep.configurer;

import io.contexa.contexaiam.asep.filter.ASEPFilter;
import io.contexa.contexaiam.asep.handler.SecurityExceptionHandlerInvoker;
import io.contexa.contexaiam.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.contexa.contexaiam.asep.handler.argumentresolver.SecurityHandlerMethodArgumentResolver;
import io.contexa.contexaiam.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.http.converter.HttpMessageConverter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Slf4j
public final class AsepConfigurer {

    private final SecurityExceptionHandlerMethodRegistry methodRegistry;
    private final List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers;
    private final List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers;
    private final List<HttpMessageConverter<?>> messageConverters;
    private ASEPFilter asepFilter;
    private int order;

    public AsepConfigurer(
            SecurityExceptionHandlerMethodRegistry methodRegistry,
            List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers,
            List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers,
            HttpMessageConverters httpMessageConverters) { // 파라미터 복원

        this.methodRegistry = Objects.requireNonNull(methodRegistry, "SecurityExceptionHandlerMethodRegistry cannot be null");
        this.defaultArgumentResolvers = defaultArgumentResolvers != null ? List.copyOf(defaultArgumentResolvers) : Collections.emptyList();
        this.defaultReturnValueHandlers = defaultReturnValueHandlers != null ? List.copyOf(defaultReturnValueHandlers) : Collections.emptyList();
        this.messageConverters = Objects.requireNonNull(httpMessageConverters, "HttpMessageConverters cannot be null").getConverters();
        this.order = Ordered.LOWEST_PRECEDENCE - 1000;

        if (this.messageConverters.isEmpty()) {
            log.warn("ASEP: HttpMessageConverter list is empty in AsepConfigurer. Body processing for ASEP responses may not work as expected.");
        }

        List<SecurityHandlerMethodArgumentResolver> finalArgumentResolvers = new ArrayList<>(this.defaultArgumentResolvers);
        AnnotationAwareOrderComparator.sort(finalArgumentResolvers);

        List<SecurityHandlerMethodReturnValueHandler> finalReturnValueHandlers = new ArrayList<>(this.defaultReturnValueHandlers);
        AnnotationAwareOrderComparator.sort(finalReturnValueHandlers);

        SecurityExceptionHandlerInvoker handlerInvoker = new SecurityExceptionHandlerInvoker(finalArgumentResolvers, finalReturnValueHandlers);
        asepFilter = new ASEPFilter(this.methodRegistry, handlerInvoker, this.messageConverters);
    }

    public AsepConfigurer order(int order) {
        this.order = order;
        return this;
    }

    public ASEPFilter asepFilter() {
        return asepFilter;
    }
}