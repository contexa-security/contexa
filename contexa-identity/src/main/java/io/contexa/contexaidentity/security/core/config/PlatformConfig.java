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
package io.contexa.contexaidentity.security.core.config;

import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public final class PlatformConfig {
    private final SafeHttpCustomizer<HttpSecurity> globalCustomizer;
    private final List<AuthenticationFlowConfig> flows;
    private PlatformContext platformContext;

    private PlatformConfig(Builder builder) {
        this.globalCustomizer = builder.globalCustomizer;
        this.flows = List.copyOf(builder.flows);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private SafeHttpCustomizer<HttpSecurity> globalCustomizer = http -> {};
        private final List<AuthenticationFlowConfig> flows = new ArrayList<>();

        public Builder global(SafeHttpCustomizer<HttpSecurity> globalCustomizer) {
            this.globalCustomizer = globalCustomizer;
            return this;
        }

        public Builder addFlow(AuthenticationFlowConfig flow) {
            Assert.notNull(flow, "AuthenticationFlowConfig cannot be null");
            this.flows.add(flow);
            return this;
        }

        public List<AuthenticationFlowConfig> getModifiableFlows() {
            return this.flows;
        }

        public Builder replaceLastFlow(AuthenticationFlowConfig flow) {
            if (!this.flows.isEmpty()) {
                this.flows.set(this.flows.size() - 1, flow);
            }
            return this;
        }

        public PlatformConfig build() {
            return new PlatformConfig(this);
        }
    }
}
