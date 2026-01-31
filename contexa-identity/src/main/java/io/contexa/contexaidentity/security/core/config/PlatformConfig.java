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
