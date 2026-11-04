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
package io.contexa.autoconfigure.core;

import io.contexa.autoconfigure.core.scope.ContexaPackages;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.transaction.TransactionAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Role;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.config.TransactionManagementConfigUtils;
import org.springframework.transaction.event.TransactionalEventListenerFactory;
import org.springframework.transaction.interceptor.BeanFactoryTransactionAttributeSourceAdvisor;
import org.springframework.transaction.interceptor.TransactionInterceptor;

import java.lang.reflect.Method;

/**
 * {@code @Transactional} for Contexa's own classes where the application has no transaction manager of its own.
 * <p>
 * Boot enables transactions when it sees a transaction manager that is a default candidate, and Contexa's is not one, so
 * that the application's injection points never get it. An application without a database of its own then had no
 * transaction advisor at all: every {@code @Transactional} of Contexa was ignored, and whatever depends on one failed
 * quietly (the count of failed sign-ins and the lock are {@code @Modifying} queries).
 * <p>
 * {@code @EnableTransactionManagement} would give every {@code @Transactional} of such an application an interceptor that
 * has no transaction manager to find, so the advisor here is narrowed to Contexa's classes, as method security is. An
 * application with transactions of its own serves Contexa's classes too, and this one stands aside.
 */
@AutoConfiguration(after = TransactionAutoConfiguration.class)
@ConditionalOnClass(BeanFactoryTransactionAttributeSourceAdvisor.class)
public class ContexaScopedTransactionAutoConfiguration {

    static final String APPLICATION_ADVISOR = TransactionManagementConfigUtils.TRANSACTION_ADVISOR_BEAN_NAME;

    @Bean(name = "contexaTransactionAdvisor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static BeanFactoryTransactionAttributeSourceAdvisor contexaTransactionAdvisor(ApplicationContext applicationContext) {
        AnnotationTransactionAttributeSource attributes = new AnnotationTransactionAttributeSource();
        TransactionInterceptor interceptor = new TransactionInterceptor();
        interceptor.setTransactionAttributeSource(attributes);
        interceptor.setBeanFactory(applicationContext);
        BeanFactoryTransactionAttributeSourceAdvisor advisor = new BeanFactoryTransactionAttributeSourceAdvisor();
        advisor.setTransactionAttributeSource(attributes);
        advisor.setAdvice(interceptor);
        // Asked when a bean is proxied: by then the application's configuration has been read.
        advisor.setClassFilter(type -> ContexaPackages.owns(type)
                && !ContexaPackages.contextHas(applicationContext, APPLICATION_ADVISOR));
        return advisor;
    }

    /** After the commit of Contexa's transaction, as such a listener says; an application's listeners stay as they were. */
    @Bean(name = "contexaTransactionalEventListenerFactory")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static TransactionalEventListenerFactory contexaTransactionalEventListenerFactory() {
        return new TransactionalEventListenerFactory() {
            @Override
            public boolean supportsMethod(Method method) {
                return ContexaPackages.owns(method.getDeclaringClass()) && super.supportsMethod(method);
            }
        };
    }
}
