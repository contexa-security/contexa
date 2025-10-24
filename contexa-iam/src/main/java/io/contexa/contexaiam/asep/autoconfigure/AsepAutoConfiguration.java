package io.contexa.contexaiam.asep.autoconfigure;

import io.contexa.contexaiam.asep.configurer.AsepConfigurer;
import io.contexa.contexaiam.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.contexa.contexaiam.asep.handler.argumentresolver.*;
import io.contexa.contexaiam.asep.handler.argumentresolver.*;
import io.contexa.contexaiam.asep.handler.returnvaluehandler.RedirectReturnValueHandler;
import io.contexa.contexaiam.asep.handler.returnvaluehandler.ResponseEntityReturnValueHandler;
import io.contexa.contexaiam.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
import io.contexa.contexaiam.asep.handler.returnvaluehandler.SecurityResponseBodyReturnValueHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.convert.ConversionService;
import org.springframework.format.support.FormattingConversionService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Configuration
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
    public SecurityExceptionHandlerMethodRegistry securityExceptionHandlerMethodRegistry() {
        log.debug("ASEP: Creating SecurityExceptionHandlerMethodRegistry bean.");
        return new SecurityExceptionHandlerMethodRegistry();
    }

    @Bean
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
    public AsepConfigurer asepConfigurer(
            SecurityExceptionHandlerMethodRegistry methodRegistry,
            @Qualifier("asepDefaultArgumentResolvers") List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers,
            @Qualifier("asepDefaultReturnValueHandlers") List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers,
            HttpMessageConverters httpMessageConverters) {
        AsepConfigurer configurer = new AsepConfigurer(
                methodRegistry,
                defaultArgumentResolvers,
                defaultReturnValueHandlers,
                httpMessageConverters
        );
        log.info("ASEP: AsepConfigurer bean (Singleton, implements SecurityConfigurer) created and configured.");
        return configurer;
    }
}