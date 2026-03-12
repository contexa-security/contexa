package io.contexa.contexaidentity.security.core.asep.configurer;

import io.contexa.contexaidentity.security.core.asep.dsl.BaseAsepAttributes;
import io.contexa.contexaidentity.security.core.asep.filter.ASEPFilter;
import io.contexa.contexaidentity.security.core.asep.handler.SecurityExceptionHandlerInvoker;
import io.contexa.contexaidentity.security.core.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.contexa.contexaidentity.security.core.asep.handler.argumentresolver.SecurityHandlerMethodArgumentResolver;
import io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.SecurityConfigurer;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.option.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.context.SecurityContextHolderFilter;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public final class AsepConfigurer implements SecurityConfigurer {

    private final SecurityExceptionHandlerMethodRegistry methodRegistry;
    private final List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers;
    private final List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers;
    private final List<HttpMessageConverter<?>> messageConverters;
    private final Map<String, Class<? extends BaseAsepAttributes>> dslAttributesMapping;
    private int order;

    public AsepConfigurer(
            SecurityExceptionHandlerMethodRegistry methodRegistry,
            List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers,
            List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers,
            HttpMessageConverters httpMessageConverters,
            Map<String, Class<? extends BaseAsepAttributes>> dslAttributesMapping) {

        this.methodRegistry = Objects.requireNonNull(methodRegistry, "SecurityExceptionHandlerMethodRegistry cannot be null");
        this.defaultArgumentResolvers = defaultArgumentResolvers != null ? List.copyOf(defaultArgumentResolvers) : Collections.emptyList();
        this.defaultReturnValueHandlers = defaultReturnValueHandlers != null ? List.copyOf(defaultReturnValueHandlers) : Collections.emptyList();
        this.messageConverters = Objects.requireNonNull(httpMessageConverters, "HttpMessageConverters cannot be null").getConverters();
        this.dslAttributesMapping = dslAttributesMapping != null ? Map.copyOf(dslAttributesMapping) : Collections.emptyMap();
        this.order = Ordered.LOWEST_PRECEDENCE - 1000;

        if (this.messageConverters.isEmpty()) {
            log.warn("ASEP: HttpMessageConverter list is empty in AsepConfigurer. Body processing for ASEP responses may not work as expected.");
        }
        if (this.dslAttributesMapping.isEmpty()) {
            log.warn("ASEP: dslAttributesMapping is empty. DSL-specific ASEP settings might not load correctly if HttpSecurity shared objects are used for attributes.");
        }
    }

    public AsepConfigurer order(int order) {
        this.order = order;
        return this;
    }

    @Override
    public void init(PlatformContext platformContext, PlatformConfig platformConfig) {

        if (this.methodRegistry == null || !this.methodRegistry.hasAnyMappings()) {
            log.warn("ASEP Init: SecurityExceptionHandlerMethodRegistry is null or has no mappings. " +
                    "@SecurityExceptionHandler methods may not be discovered or effective. Ensure @SecurityControllerAdvice beans with @SecurityExceptionHandler methods are correctly configured.");
        }
        if (this.messageConverters.isEmpty()) {
            log.warn("ASEP Init: No HttpMessageConverters available. Response body generation for ASEP might fail. " +
                    "Ensure HttpMessageConverters are correctly configured in the Spring context (e.g., via HttpMessageConvertersAutoConfiguration).");
        }
    }

    @Override
    public void configure(FlowContext flowCtx) throws Exception {
        Objects.requireNonNull(flowCtx, "FlowContext cannot be null");
        HttpSecurity http = Objects.requireNonNull(flowCtx.http(), "HttpSecurity from FlowContext cannot be null");
        AuthenticationFlowConfig flowConfig = Objects.requireNonNull(flowCtx.flow(), "AuthenticationFlowConfig from FlowContext cannot be null");
        String flowTypeName = Objects.requireNonNull(flowConfig.getTypeName(), "Flow typeName cannot be null").toLowerCase();

        List<SecurityHandlerMethodArgumentResolver> collectedCustomArgumentResolvers = new ArrayList<>();
        List<SecurityHandlerMethodReturnValueHandler> collectedCustomReturnValueHandlers = new ArrayList<>();

        BaseAsepAttributes flowSpecificAsepAttributes = null;

        if ("mfa".equalsIgnoreCase(flowTypeName)) {
            flowSpecificAsepAttributes = flowConfig.getMfaAsepAttributes();
            if (flowSpecificAsepAttributes != null) {
            }
        } else if (!flowConfig.getStepConfigs().isEmpty()) {
            AuthenticationStepConfig mainStep = flowConfig.getStepConfigs().get(0);
            Object optionsObject = mainStep.getOptions().get("_options");

            if (optionsObject instanceof FormOptions fo) flowSpecificAsepAttributes = fo.getAsepAttributes();
            else if (optionsObject instanceof RestOptions ro) flowSpecificAsepAttributes = ro.getAsepAttributes();
            else if (optionsObject instanceof OttOptions oo) flowSpecificAsepAttributes = oo.getAsepAttributes();
            else if (optionsObject instanceof PasskeyOptions po) flowSpecificAsepAttributes = po.getAsepAttributes();

            if (flowSpecificAsepAttributes != null) {
            }
        }

        if (flowSpecificAsepAttributes != null) {
            collectedCustomArgumentResolvers.addAll(flowSpecificAsepAttributes.getCustomArgumentResolvers());
            collectedCustomReturnValueHandlers.addAll(flowSpecificAsepAttributes.getCustomReturnValueHandlers());
        } else {
        }

        List<SecurityHandlerMethodArgumentResolver> finalArgumentResolvers = new ArrayList<>(this.defaultArgumentResolvers);
        collectedCustomArgumentResolvers.forEach(customRes -> {
            finalArgumentResolvers.removeIf(defaultRes -> defaultRes.getClass().equals(customRes.getClass()));
            finalArgumentResolvers.add(customRes);
        });
        AnnotationAwareOrderComparator.sort(finalArgumentResolvers);

        List<SecurityHandlerMethodReturnValueHandler> finalReturnValueHandlers = new ArrayList<>(this.defaultReturnValueHandlers);
        collectedCustomReturnValueHandlers.forEach(customHandler -> {
            finalReturnValueHandlers.removeIf(defaultHandler -> defaultHandler.getClass().equals(customHandler.getClass()));
            finalReturnValueHandlers.add(customHandler);
        });
        AnnotationAwareOrderComparator.sort(finalReturnValueHandlers);

        if (log.isDebugEnabled()) {
        }

        SecurityExceptionHandlerInvoker handlerInvoker = new SecurityExceptionHandlerInvoker(finalArgumentResolvers, finalReturnValueHandlers);
        ASEPFilter asepFilter = new ASEPFilter(this.methodRegistry, handlerInvoker, this.messageConverters);

    }

    @Override
    public int getOrder() {
        return this.order;
    }
}