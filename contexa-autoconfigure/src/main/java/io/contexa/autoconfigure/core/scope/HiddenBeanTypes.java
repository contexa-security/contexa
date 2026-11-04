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

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.util.ClassUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;

/**
 * A view of a bean factory in which the beans of one type are not listed.
 * <p>
 * Spring's annotation processors apply every configurer bean of the container ({@code SchedulingConfigurer},
 * {@code KafkaListenerConfigurer}) to the registrar they own. A configurer is the application's code for the application's processor:
 * applied to the registrar of Contexa's processor as well, it would register the application's tasks and endpoints a second time (or, when
 * the application never switched the support on, bring them to life). Contexa's processors are given this view, so they see no configurers
 * and everything else as it is.
 */
final class HiddenBeanTypes {

    private HiddenBeanTypes() {
    }

    static BeanFactory hiding(BeanFactory delegate, Class<?> hidden) {
        if (!(delegate instanceof ListableBeanFactory)) {
            return delegate;
        }
        return (BeanFactory) Proxy.newProxyInstance(delegate.getClass().getClassLoader(), ClassUtils.getAllInterfaces(delegate), (proxy, method, args) -> {
            if ("getBeansOfType".equals(method.getName()) && args != null && args.length > 0 && hidden.equals(args[0])) {
                return new LinkedHashMap<String, Object>();
            }
            try {
                return method.invoke(delegate, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        });
    }
}
