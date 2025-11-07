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
    private final Map<String, Class<? extends BaseAsepAttributes>> dslAttributesMapping; // 파라미터 및 필드 복원
    private int order;

    public AsepConfigurer(
            SecurityExceptionHandlerMethodRegistry methodRegistry,
            List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers,
            List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers,
            HttpMessageConverters httpMessageConverters,
            Map<String, Class<? extends BaseAsepAttributes>> dslAttributesMapping) { // 파라미터 복원

        this.methodRegistry = Objects.requireNonNull(methodRegistry, "SecurityExceptionHandlerMethodRegistry cannot be null");
        this.defaultArgumentResolvers = defaultArgumentResolvers != null ? List.copyOf(defaultArgumentResolvers) : Collections.emptyList();
        this.defaultReturnValueHandlers = defaultReturnValueHandlers != null ? List.copyOf(defaultReturnValueHandlers) : Collections.emptyList();
        this.messageConverters = Objects.requireNonNull(httpMessageConverters, "HttpMessageConverters cannot be null").getConverters();
        this.dslAttributesMapping = dslAttributesMapping != null ? Map.copyOf(dslAttributesMapping) : Collections.emptyMap(); // 필드 복원
        this.order = Ordered.LOWEST_PRECEDENCE - 1000;

        if (this.messageConverters.isEmpty()) {
            log.warn("ASEP: HttpMessageConverter list is empty in AsepConfigurer. Body processing for ASEP responses may not work as expected.");
        }
        if (this.dslAttributesMapping.isEmpty()) { // 복원된 필드 사용
            log.warn("ASEP: dslAttributesMapping is empty. DSL-specific ASEP settings might not load correctly if HttpSecurity shared objects are used for attributes.");
        }
    }

    public AsepConfigurer order(int order) {
        this.order = order;
        return this;
    }

    @Override
    public void init(PlatformContext platformContext, PlatformConfig platformConfig) {
        log.info("ASEP: AsepConfigurer (Singleton Bean) initializing... Effective order: {}", this.order);
        log.debug("  - Default ArgumentResolvers count: {}", this.defaultArgumentResolvers.size());
        log.debug("  - Default ReturnValueHandlers count: {}", this.defaultReturnValueHandlers.size());
        log.debug("  - DSL Attributes Mapping count: {}", this.dslAttributesMapping.size()); // 복원된 필드 사용
        log.debug("  - MessageConverters count: {}", this.messageConverters.size());

        if (this.methodRegistry == null || !this.methodRegistry.hasAnyMappings()) {
            log.warn("ASEP Init: SecurityExceptionHandlerMethodRegistry is null or has no mappings. " +
                    "@SecurityExceptionHandler methods may not be discovered or effective. Ensure @SecurityControllerAdvice beans with @SecurityExceptionHandler methods are correctly configured.");
        }
        if (this.messageConverters.isEmpty()) {
            log.warn("ASEP Init: No HttpMessageConverters available. Response body generation for ASEP might fail. " +
                    "Ensure HttpMessageConverters are correctly configured in the Spring context (e.g., via HttpMessageConvertersAutoConfiguration).");
        }
        log.info("ASEP: AsepConfigurer initialized successfully.");
    }

    @Override
    public void configure(FlowContext flowCtx) throws Exception {
        Objects.requireNonNull(flowCtx, "FlowContext cannot be null");
        HttpSecurity http = Objects.requireNonNull(flowCtx.http(), "HttpSecurity from FlowContext cannot be null");
        AuthenticationFlowConfig flowConfig = Objects.requireNonNull(flowCtx.flow(), "AuthenticationFlowConfig from FlowContext cannot be null");
        String flowTypeName = Objects.requireNonNull(flowConfig.getTypeName(), "Flow typeName cannot be null").toLowerCase(); // 일관성을 위해 소문자 사용

        log.debug("ASEP: Applying AsepConfigurer to flow: {} (HttpSecurity hash: {})", flowTypeName, http.hashCode());

        List<SecurityHandlerMethodArgumentResolver> collectedCustomArgumentResolvers = new ArrayList<>();
        List<SecurityHandlerMethodReturnValueHandler> collectedCustomReturnValueHandlers = new ArrayList<>();

        BaseAsepAttributes flowSpecificAsepAttributes = null;

        // 방법 1: dslAttributesMapping과 HttpSecurity.getSharedObject() 사용 (이전 방식)
        // Class<? extends BaseAsepAttributes> attributesClassKey = this.dslAttributesMapping.get(flowTypeName);
        // if (attributesClassKey != null) {
        //     Object attributesObject = http.getSharedObject(attributesClassKey);
        //     if (attributesObject instanceof BaseAsepAttributes) {
        //         flowSpecificAsepAttributes = (BaseAsepAttributes) attributesObject;
        //         log.info("ASEP: Loaded ASEP attributes from HttpSecurity.sharedObject (type: {}) for flow [{}].", attributesClassKey.getSimpleName(), flowTypeName);
        //     }
        // }

        // 방법 2: FlowConfig의 Options 객체에서 ASEP 속성을 직접 가져오기 (권장된 최신 방식)
        if ("mfa".equalsIgnoreCase(flowTypeName)) {
            flowSpecificAsepAttributes = flowConfig.getMfaAsepAttributes();
            if (flowSpecificAsepAttributes != null) {
                log.info("ASEP: Loaded global MfaAsepAttributes from AuthenticationFlowConfig for MFA flow [{}].", flowTypeName);
            }
        } else if (!flowConfig.getStepConfigs().isEmpty()) {
            AuthenticationStepConfig mainStep = flowConfig.getStepConfigs().get(0);
            Object optionsObject = mainStep.getOptions().get("_options");

            // 각 XxxOptions 클래스에 getAsepAttributes() 메서드가 정의되어 있다고 가정
            if (optionsObject instanceof FormOptions fo) flowSpecificAsepAttributes = fo.getAsepAttributes();
            else if (optionsObject instanceof RestOptions ro) flowSpecificAsepAttributes = ro.getAsepAttributes();
            else if (optionsObject instanceof OttOptions oo) flowSpecificAsepAttributes = oo.getAsepAttributes();
            else if (optionsObject instanceof PasskeyOptions po) flowSpecificAsepAttributes = po.getAsepAttributes();
//            else if (optionsObject instanceof RecoveryCodeOptions rco) flowSpecificAsepAttributes = rco.getAsepAttributes();
            // ... 다른 XxxOptions 타입에 대한 처리
            if (flowSpecificAsepAttributes != null) {
                log.info("ASEP: Loaded ASEP attributes from Options object ({}) for flow [{}].", optionsObject.getClass().getSimpleName(), flowTypeName);
            }
        }


        if (flowSpecificAsepAttributes != null) {
            collectedCustomArgumentResolvers.addAll(flowSpecificAsepAttributes.getCustomArgumentResolvers());
            collectedCustomReturnValueHandlers.addAll(flowSpecificAsepAttributes.getCustomReturnValueHandlers());
            log.info("ASEP: Using custom ASEP settings for flow [{}]. ArgResolvers: {}, RetValHandlers: {}",
                    flowTypeName,
                    collectedCustomArgumentResolvers.size(), collectedCustomReturnValueHandlers.size());
        } else {
            log.debug("ASEP: No specific ASEP attributes found for flow [{}]. Using defaults only.", flowTypeName);
        }

        // 최종 Resolver/Handler 리스트 구성
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
            log.debug("ASEP: Final ArgumentResolvers for flow [{}]: Count = {}. List: {}", flowTypeName, finalArgumentResolvers.size(),
                    finalArgumentResolvers.stream().map(r -> r.getClass().getSimpleName()).collect(Collectors.toList()));
            log.debug("ASEP: Final ReturnValueHandlers for flow [{}]: Count = {}. List: {}", flowTypeName, finalReturnValueHandlers.size(),
                    finalReturnValueHandlers.stream().map(h -> h.getClass().getSimpleName()).collect(Collectors.toList()));
        }

        SecurityExceptionHandlerInvoker handlerInvoker = new SecurityExceptionHandlerInvoker(finalArgumentResolvers, finalReturnValueHandlers);
        ASEPFilter asepFilter = new ASEPFilter(this.methodRegistry, handlerInvoker, this.messageConverters);

//        http.addFilterAfter(asepFilter, SecurityContextHolderFilter.class);
        log.info("ASEP: ASEPFilter added by AsepConfigurer for flow: {}", flowTypeName);
    }

    @Override
    public int getOrder() {
        return this.order;
    }
}