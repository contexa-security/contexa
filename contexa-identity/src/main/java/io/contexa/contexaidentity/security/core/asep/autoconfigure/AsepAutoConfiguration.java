package io.contexa.contexaidentity.security.core.asep.autoconfigure;

import io.contexa.contexaidentity.security.core.asep.configurer.AsepConfigurer;
import io.contexa.contexaidentity.security.core.asep.dsl.*;
import io.contexa.contexaidentity.security.core.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.contexa.contexaidentity.security.core.asep.handler.argumentresolver.*;
import io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler.RedirectReturnValueHandler;
import io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler.ResponseEntityReturnValueHandler;
import io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
import io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler.SecurityResponseBodyReturnValueHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.convert.ConversionService;
import org.springframework.format.support.FormattingConversionService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.*;

@AutoConfiguration // Spring Boot 2.7+
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({HttpSecurity.class}) // HttpSecurity가 classpath에 있어야 활성화
@Slf4j
public class AsepAutoConfiguration {

    private final HttpMessageConverters httpMessageConverters;
    private final ConversionService conversionService;

    // 생성자 주입 방식 권장
    public AsepAutoConfiguration(ObjectProvider<HttpMessageConverters> httpMessageConvertersProvider,
                                 ObjectProvider<ConversionService> conversionServiceProvider) {
        this.httpMessageConverters = httpMessageConvertersProvider.getIfAvailable(() -> new HttpMessageConverters(Collections.emptyList()));
        this.conversionService = conversionServiceProvider.getIfAvailable(FormattingConversionService::new);
        log.info("ASEP: AsepAutoConfiguration initialized. HttpMessageConverters count: {}, ConversionService: {}",
                this.httpMessageConverters.getConverters().size(), this.conversionService.getClass().getSimpleName());
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityExceptionHandlerMethodRegistry securityExceptionHandlerMethodRegistry() {
        log.debug("ASEP: Creating SecurityExceptionHandlerMethodRegistry bean.");
        return new SecurityExceptionHandlerMethodRegistry();
    }

    @Bean
    @ConditionalOnMissingBean(name = "asepDefaultArgumentResolvers")
    public List<SecurityHandlerMethodArgumentResolver> asepDefaultArgumentResolvers() {
        List<SecurityHandlerMethodArgumentResolver> resolvers = new ArrayList<>();
        resolvers.add(new CaughtExceptionArgumentResolver());
        resolvers.add(new AuthenticationObjectArgumentResolver());
        resolvers.add(new HttpServletRequestArgumentResolver());
        resolvers.add(new HttpServletResponseArgumentResolver());
        resolvers.add(new SecurityPrincipalArgumentResolver());
        resolvers.add(new SecurityRequestHeaderArgumentResolver(this.conversionService));
        resolvers.add(new SecurityCookieValueArgumentResolver(this.conversionService));
        resolvers.add(new SecurityRequestAttributeArgumentResolver());
        resolvers.add(new SecuritySessionAttributeArgumentResolver());
        // SecurityRequestBodyArgumentResolver는 messageConverters를 필요로 함
        if (this.httpMessageConverters != null && !this.httpMessageConverters.getConverters().isEmpty()) {
            resolvers.add(new SecurityRequestBodyArgumentResolver(this.httpMessageConverters.getConverters()));
        } else {
            log.warn("ASEP: HttpMessageConverters bean not available or empty. SecurityRequestBodyArgumentResolver will not be fully functional.");
            resolvers.add(new SecurityRequestBodyArgumentResolver(Collections.emptyList())); // 빈 리스트로라도 생성
        }
        AnnotationAwareOrderComparator.sort(resolvers);
        log.debug("ASEP: Created 'asepDefaultArgumentResolvers' bean with {} resolvers.", resolvers.size());
        return Collections.unmodifiableList(resolvers);
    }

    @Bean
    @ConditionalOnMissingBean(name = "asepDefaultReturnValueHandlers")
    public List<SecurityHandlerMethodReturnValueHandler> asepDefaultReturnValueHandlers() {
        List<SecurityHandlerMethodReturnValueHandler> handlers = new ArrayList<>();
        if (this.httpMessageConverters != null && !this.httpMessageConverters.getConverters().isEmpty()) {
            handlers.add(new ResponseEntityReturnValueHandler(this.httpMessageConverters.getConverters()));
            handlers.add(new SecurityResponseBodyReturnValueHandler(this.httpMessageConverters.getConverters()));
        } else {
            log.warn("ASEP: HttpMessageConverters bean not available or empty. ResponseEntityReturnValueHandler and SecurityResponseBodyReturnValueHandler will not be fully functional.");
            handlers.add(new ResponseEntityReturnValueHandler(Collections.emptyList()));
            handlers.add(new SecurityResponseBodyReturnValueHandler(Collections.emptyList()));
        }
        handlers.add(new RedirectReturnValueHandler());
        AnnotationAwareOrderComparator.sort(handlers);
        log.debug("ASEP: Created 'asepDefaultReturnValueHandlers' bean with {} handlers.", handlers.size());
        return Collections.unmodifiableList(handlers);
    }

    @Bean
    @ConditionalOnMissingBean(name = "asepDslAttributesMapping")
    public Map<String, Class<? extends BaseAsepAttributes>> asepDslAttributesMapping() {
        Map<String, Class<? extends BaseAsepAttributes>> mapping = new HashMap<>();
        // 플랫폼의 AuthenticationFlowConfig.getTypeName()과 일치해야 함 (소문자 권장)
        mapping.put("form", FormAsepAttributes.class);
        mapping.put("rest", RestAsepAttributes.class);
        mapping.put("ott", OttAsepAttributes.class);
        mapping.put("passkey", PasskeyAsepAttributes.class);
        mapping.put("mfa", MfaAsepAttributes.class); // MFA 플로우 전체 ASEP
        // MFA 내부 Factor별 ASEP (선택적, XxxOptions에 직접 저장하는 방식이면 이 매핑은 불필요할 수 있음)
        // mapping.put("mfa-ott", MfaOttAsepAttributes.class);
        // mapping.put("mfa-passkey", MfaPasskeyAsepAttributes.class);
        log.info("ASEP: Initialized 'asepDslAttributesMapping' ({} entries). Keys: {}", mapping.size(), mapping.keySet());
        return Collections.unmodifiableMap(mapping);
    }

    @Bean
    @ConditionalOnMissingBean
    public AsepConfigurer asepConfigurer(
            SecurityExceptionHandlerMethodRegistry methodRegistry,
            @Qualifier("asepDefaultArgumentResolvers") List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers,
            @Qualifier("asepDefaultReturnValueHandlers") List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers,
            HttpMessageConverters httpMessageConverters, // Spring Boot가 자동 구성한 HttpMessageConverters 주입
            @Qualifier("asepDslAttributesMapping") Map<String, Class<? extends BaseAsepAttributes>> dslAttributesMapping) { // dslAttributesMapping 파라미터 복원
        AsepConfigurer configurer = new AsepConfigurer(
                methodRegistry,
                defaultArgumentResolvers,
                defaultReturnValueHandlers,
                httpMessageConverters, // 생성자에 전달
                dslAttributesMapping // 생성자에 전달
        );
        log.info("ASEP: AsepConfigurer bean (Singleton, implements SecurityConfigurer) created and configured.");
        return configurer;
    }
}