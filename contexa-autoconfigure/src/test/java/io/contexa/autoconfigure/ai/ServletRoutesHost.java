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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

/**
 * An application on the servlet stack with the functional routes of Spring MVC, for
 * {@link ReactiveRoutesDefinitionCheckTest}: they carry the names the routes of WebFlux carry and are not those.
 */
@Configuration(proxyBeanMethods = false)
class ServletRoutesHost {

    static final String ROUTES = "mvcRoutes";

    @Bean(name = ROUTES)
    RouterFunction<ServerResponse> mvcRoutes() {
        return RouterFunctions.route().GET("/orders", request -> ServerResponse.ok().build()).build();
    }

    @Bean
    ReactiveRoutesDefinitionCheckTest.Installed installed() {
        return new ReactiveRoutesDefinitionCheckTest.Installed();
    }
}
