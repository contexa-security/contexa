package io.contexa.contexaidentity.security.core.asep.autoconfigure;

import io.contexa.contexaidentity.security.core.asep.configurer.AsepConfigurer;
import io.contexa.contexaidentity.security.core.asep.dsl.*;
import io.contexa.contexaidentity.security.core.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.contexa.contexaidentity.security.core.asep.handler.argumentresolver.*;
import io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler.RedirectReturnValueHandler;
import io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler.ResponseEntityReturnValueHandler;
import io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
import io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler.SecurityResponseBodyReturnValueHandler;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.FlowConfigurer;
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

@AutoConfiguration 
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({HttpSecurity.class}) 
@Slf4j
public class AsepAutoConfiguration {

    private final HttpMessageConverters httpMessageConverters;
    private final ConversionService conversionService;

    public AsepAutoConfiguration(ObjectProvider<HttpMessageConverters> httpMessageConvertersProvider,
                                 ObjectProvider<ConversionService> conversionServiceProvider) {
        this.httpMessageConverters = httpMessageConvertersProvider.getIfAvailable(() -> new HttpMessageConverters(Collections.emptyList()));
        this.conversionService = conversionServiceProvider.getIfAvailable(FormattingConversionService::new);
            }

    @Bean
    @ConditionalOnMissingBean
    public SecurityExceptionHandlerMethodRegistry securityExceptionHandlerMethodRegistry() {
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
        
        if (this.httpMessageConverters != null && !this.httpMessageConverters.getConverters().isEmpty()) {
            resolvers.add(new SecurityRequestBodyArgumentResolver(this.httpMessageConverters.getConverters()));
        } else {
            log.warn("ASEP: HttpMessageConverters bean not available or empty. SecurityRequestBodyArgumentResolver will not be fully functional.");
            resolvers.add(new SecurityRequestBodyArgumentResolver(Collections.emptyList())); 
        }
        AnnotationAwareOrderComparator.sort(resolvers);
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
                return Collections.unmodifiableList(handlers);
    }

    @Bean
    @ConditionalOnMissingBean(name = "asepDslAttributesMapping")
    public Map<String, Class<? extends BaseAsepAttributes>> asepDslAttributesMapping() {
        Map<String, Class<? extends BaseAsepAttributes>> mapping = new HashMap<>();
        
        mapping.put("form", FormAsepAttributes.class);
        mapping.put("rest", RestAsepAttributes.class);
        mapping.put("ott", OttAsepAttributes.class);
        mapping.put("passkey", PasskeyAsepAttributes.class);
        mapping.put("mfa", MfaAsepAttributes.class); 

                return Collections.unmodifiableMap(mapping);
    }

    @Bean
    @ConditionalOnMissingBean(AsepConfigurer.class)
    public AsepConfigurer asepConfigurer(
            SecurityExceptionHandlerMethodRegistry methodRegistry,
            @Qualifier("asepDefaultArgumentResolvers") List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers,
            @Qualifier("asepDefaultReturnValueHandlers") List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers,
            HttpMessageConverters httpMessageConverters, 
            @Qualifier("asepDslAttributesMapping") Map<String, Class<? extends BaseAsepAttributes>> dslAttributesMapping) { 
        AsepConfigurer configurer = new AsepConfigurer(
                methodRegistry,
                defaultArgumentResolvers,
                defaultReturnValueHandlers,
                httpMessageConverters, 
                dslAttributesMapping 
        );
                return configurer;
    }
}