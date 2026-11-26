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
package io.contexa.autoconfigure.ai;

import jakarta.servlet.DispatcherType;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

/**
 * Contexa's one servlet filter registration behind the Spring Security filter chain and behind every filter of the
 * application's (R-10 of docs/agent/운영모드-정상화-구현계획.md), in every way of running Contexa. Its members are the
 * {@link ContexaSlotFilterRegistration} beans, wherever they are defined.
 */
@Configuration(proxyBeanMethods = false)
public class ContexaFilterSlotConfiguration {

    /** The name of the slot's registration bean. */
    public static final String REGISTRATION_BEAN = "contexaFilterSlotRegistration";

    /**
     * After every other filter mapping of the servlet context, whatever its order: the servlet API's "match after", which
     * the application's registrations leave off. The application's filters, its sign-in among them, have all run when
     * Contexa decides, so the order they are given changes nothing in what Contexa does. The order is the last one as well,
     * for what sorts the registrations without mapping them (a MockMvc set up from the context). It is on every path and
     * for every dispatch: each member is then given only the requests of its own registration.
     */
    @Bean(name = "contexaFilterSlotRegistration")
    @ConditionalOnMissingBean(name = "contexaFilterSlotRegistration")
    public FilterRegistrationBean<ContexaFilterSlot> filterSlotRegistration(ListableBeanFactory beanFactory,
                                                                            ObjectProvider<SecurityProperties> securityProperties) {
        FilterRegistrationBean<ContexaFilterSlot> registration =
                new FilterRegistrationBean<>(new ContexaFilterSlot(() -> members(beanFactory)));
        registration.setName(ContexaFilterSlot.NAME);
        registration.setOrder(Ordered.LOWEST_PRECEDENCE);
        registration.setMatchAfter(true);
        registration.addUrlPatterns("/*");
        registration.setDispatcherTypes(EnumSet.allOf(DispatcherType.class));
        return registration;
    }

    private static List<ContexaSlotFilterRegistration<?>> members(ListableBeanFactory beanFactory) {
        List<ContexaSlotFilterRegistration<?>> members = new ArrayList<>();
        for (ContexaSlotFilterRegistration<?> member : beanFactory.getBeansOfType(ContexaSlotFilterRegistration.class).values()) {
            members.add(member);
        }
        return members;
    }
}
