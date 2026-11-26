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

import jakarta.servlet.Filter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

/**
 * The registration of a filter of Contexa's that runs behind the Spring Security filter chain (R-10 of
 * docs/agent/운영모드-정상화-구현계획.md). The servlet container never maps it on its own: {@link ContexaFilterSlot} runs it
 * among Contexa's other such filters, by {@link #getOrder()}, on the requests its URL patterns and dispatcher types name,
 * under its name and with its init parameters, as the container would. Being a {@link FilterRegistrationBean}, it also
 * keeps Spring Boot from registering the filter bean it holds on its own. As with any registration, {@code setEnabled(false)}
 * switches the filter off: the slot then leaves it out ({@link #runsInSlot()}).
 *
 * @param <T> the type of the filter
 */
public class ContexaSlotFilterRegistration<T extends Filter> extends FilterRegistrationBean<T> {

    private boolean runsInSlot = true;

    public ContexaSlotFilterRegistration(T filter) {
        super(filter);
    }

    /** Whether {@link ContexaFilterSlot} runs the filter. */
    @Override
    public void setEnabled(boolean enabled) {
        this.runsInSlot = enabled;
    }

    /** Always {@code false}: the servlet container never maps the filter on its own ({@link #runsInSlot()} tells whether it runs). */
    @Override
    public boolean isEnabled() {
        return false;
    }

    public boolean runsInSlot() {
        return runsInSlot;
    }

    @Override
    protected String getDescription() {
        return super.getDescription() + ", run inside " + ContexaFilterSlot.NAME;
    }
}
