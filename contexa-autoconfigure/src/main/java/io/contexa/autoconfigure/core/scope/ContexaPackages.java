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

import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.HierarchicalBeanFactory;

/**
 * Which classes are Contexa's: those of the Contexa libraries. The scheduling, asynchronous and caching support Contexa brings is applied
 * to these classes only, so that annotations in the application stay as dormant as the application left them.
 */
public final class ContexaPackages {

    /** The packages of the Contexa libraries (applications of Contexa's own, such as the showcase and the site, are others). */
    public static final String[] OWN = {"io.contexa.contexa", "io.contexa.autoconfigure"};

    private ContexaPackages() {
    }

    public static boolean owns(String className) {
        if (className == null) {
            return false;
        }
        for (String prefix : OWN) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    public static boolean owns(Class<?> type) {
        return type != null && owns(type.getName());
    }

    /**
     * Whether the context already has the bean. Asked when a bean is processed, not when the auto-configuration is evaluated: an
     * application, or a library's auto-configuration that happens to come after Contexa's, may switch the same support on later,
     * and Contexa's processor must then leave the beans to it instead of applying the annotation a second time.
     */
    public static boolean contextHas(BeanFactory beanFactory, String beanName) {
        if (beanFactory instanceof HierarchicalBeanFactory hierarchical) {
            // A processor serves the beans of its own context only: support in a parent context does not serve the beans of this one.
            return hierarchical.containsLocalBean(beanName);
        }
        return beanFactory != null && beanFactory.containsBean(beanName);
    }

    /** The class of a bean behind its proxies. */
    public static boolean ownsBean(Object bean) {
        return owns(AopUtils.getTargetClass(bean));
    }
}
