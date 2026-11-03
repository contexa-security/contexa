/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.core.scope;

import org.springframework.aop.framework.autoproxy.AbstractBeanFactoryAwareAdvisingPostProcessor;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.AnnotationCacheOperationSource;
import org.springframework.cache.interceptor.BeanFactoryCacheOperationSourceAdvisor;
import org.springframework.cache.config.CacheManagementConfigUtils;
import org.springframework.cache.interceptor.CacheInterceptor;

/**
 * {@code @Cacheable}, {@code @CacheEvict} and {@code @CachePut} for Contexa's own beans, without {@code @EnableCaching} for the
 * application: the application's methods with these annotations stay uncached when the application never turned caching on, and no
 * cache manager appears in the application because of Contexa (the interceptor is not a bean, so Spring Boot's cache configuration is not
 * switched on either).
 */
public class ContexaCacheAnnotationBeanPostProcessor extends AbstractBeanFactoryAwareAdvisingPostProcessor {

    private final CacheInterceptor interceptor = new CacheInterceptor();
    private BeanFactory beanFactory;

    public ContexaCacheAnnotationBeanPostProcessor(CacheManager cacheManager) {
        AnnotationCacheOperationSource source = new AnnotationCacheOperationSource();
        interceptor.setCacheManager(cacheManager);
        interceptor.setCacheOperationSources(source);
        BeanFactoryCacheOperationSourceAdvisor advisor = new BeanFactoryCacheOperationSourceAdvisor();
        advisor.setCacheOperationSource(source);
        advisor.setAdvice(interceptor);
        this.advisor = advisor;
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) {
        super.setBeanFactory(beanFactory);
        this.beanFactory = beanFactory;
        interceptor.setBeanFactory(beanFactory);
        interceptor.afterSingletonsInstantiated();
    }

    @Override
    protected boolean isEligible(Class<?> targetClass) {
        return ContexaPackages.owns(targetClass)
                && !ContexaPackages.contextHas(beanFactory, CacheManagementConfigUtils.CACHE_ADVISOR_BEAN_NAME)
                && super.isEligible(targetClass);
    }
}
