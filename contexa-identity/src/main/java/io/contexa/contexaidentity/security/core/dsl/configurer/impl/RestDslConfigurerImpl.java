package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.core.asep.dsl.RestAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.RestDslConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.context.SecurityContextRepository;

@Slf4j
public final class RestDslConfigurerImpl // <H extends HttpSecurityBuilder<H>> 제네릭 제거 또는 유지
        extends AbstractOptionsBuilderConfigurer<RestDslConfigurerImpl, RestOptions, RestOptions.Builder, RestDslConfigurer>
        implements RestDslConfigurer {

    /**
     * 단일 인증용 생성자 (기본)
     */
    public RestDslConfigurerImpl(ApplicationContext applicationContext) {
        super(RestOptions.builder(applicationContext));
        setApplicationContext(applicationContext);
    }

    /**
     * MFA 1차 인증용 생성자
     * @param applicationContext ApplicationContext
     * @param isMfaMode true: MFA 1차 인증, false: 단일 인증 (사용하지 않음)
     */
    public RestDslConfigurerImpl(ApplicationContext applicationContext, boolean isMfaMode) {
        super(isMfaMode ? RestOptions.builderForMfa(applicationContext) : RestOptions.builder(applicationContext));
        setApplicationContext(applicationContext);
    }

    @Override
    public RestDslConfigurer order(int order) {
        getOptionsBuilder().order(order); // AuthenticationProcessingOptions.Builder의 order 사용
        return self();
    }

    @Override
    public RestDslConfigurer loginProcessingUrl(String url) {
        super.loginProcessingUrl(url); // AbstractOptionsBuilderConfigurer의 메서드 호출
        return self();
    }

    @Override
    public RestDslConfigurer successHandler(PlatformAuthenticationSuccessHandler  successHandler) {
        super.successHandler(successHandler);
        return self();
    }

    @Override
    public RestDslConfigurer failureHandler(PlatformAuthenticationFailureHandler failureHandler) {
        super.failureHandler(failureHandler);
        return self();
    }

    @Override
    public RestDslConfigurer securityContextRepository(SecurityContextRepository repository) {
        super.securityContextRepository(repository);
        return self();
    }

    @Override
    public RestDslConfigurer asep(Customizer<RestAsepAttributes> restAsepAttributesCustomizer){
        // H builder = getBuilder(); // 제거
        RestAsepAttributes attributes = new RestAsepAttributes();
        if (restAsepAttributesCustomizer != null) {
            restAsepAttributesCustomizer.customize(attributes);
        }
        // builder.setSharedObject(RestAsepAttributes.class, attributes); // 제거
        getOptionsBuilder().asepAttributes(attributes); // RestOptions.Builder에 저장
        log.debug("ASEP: RestAsepAttributes configured and will be stored within RestOptions.");
        return self();
    }

    @Override
    protected RestDslConfigurerImpl self() {
        return this;
    }

    // configure(H builder) 메서드는 AbstractOptionsBuilderConfigurer에서 제거되었으므로 여기서도 불필요
}

