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
package io.contexa.contexaidentity.security.core.context;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;
import java.util.Map;

public interface PlatformContext {

    void addAuthConfig(AuthenticationStepConfig config);

    List<AuthenticationStepConfig> getAuthConfigs();

    <T> void share(Class<T> clz, T obj);

    <T> T getShared(Class<T> clz);

    void registerHttp(AuthenticationFlowConfig flow, HttpSecurity http);

    HttpSecurity http(AuthenticationFlowConfig flow);

    List<FlowContext> flowContexts();

    void flowContexts(List<FlowContext> flowContexts);

    HttpSecurity newHttp();

    void registerChain(String id, SecurityFilterChain chain);

    Map<String, SecurityFilterChain> getChains();

    ApplicationContext applicationContext();
}

