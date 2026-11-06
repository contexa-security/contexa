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
package io.contexa.autoconfigure.identity;

import org.springframework.core.Ordered;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * A token customizer of the application, kept out of the bean type the authorization server looks for. The server takes
 * one customizer bean and refuses to start with two; Contexa's own composed customizer is that one, and it runs the
 * application's customizers after its own checks. The wrapper keeps the order the application gave: its
 * {@code @Order}, or the customizer's own {@link Ordered}.
 */
final class HostTokenCustomizer implements Ordered {

    private final OAuth2TokenCustomizer<JwtEncodingContext> customizer;
    private final int order;

    HostTokenCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> customizer, int order) {
        this.customizer = customizer;
        this.order = order;
    }

    void customize(JwtEncodingContext context) {
        customizer.customize(context);
    }

    @Override
    public int getOrder() {
        return customizer instanceof Ordered ordered ? ordered.getOrder() : order;
    }
}
