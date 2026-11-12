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

import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;

/**
 * Refuses the functional routes of a WebFlux application from their bean definitions, before a single bean is created.
 * {@link OwnershipStartupDiagnostics} refuses them too, but only when every bean exists, and by then Contexa has installed
 * its tables and seed rows in its database and the application has done its own start-up work: a start that is refused
 * should leave nothing behind.
 * <p>
 * It asks what the later refusal asks, by the type the beans are declared as, and creates none of them. Routes an
 * application declares as something wider than a router function are not seen here and are left to the later refusal, and
 * so is a start whose definitions cannot be read.
 */
public class ReactiveRoutesDefinitionCheck implements BeanFactoryPostProcessor, PriorityOrdered {

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
        String[] routes;
        try {
            routes = OwnershipStartupDiagnostics.reactiveRoutes(beanFactory, getClass().getClassLoader());
        } catch (RuntimeException | LinkageError e) {
            // what cannot be read is left to the later refusal, which decides when the beans exist
            return;
        }
        if (routes.length > 0) {
            throw OwnershipStartupDiagnostics.reactiveRoutesRefused(routes);
        }
    }
}
