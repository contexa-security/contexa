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
package io.contexa.contexacore.autonomous.event.support;

import io.contexa.contexacommon.domain.EventTimeZone;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.StringUtils;

import java.time.ZoneId;

/**
 * Registers the configured company time zone for reading event times, and clears it when the context closes. An
 * unknown time zone id fails the start.
 */
public class EventTimeZoneRegistrar implements InitializingBean, DisposableBean {

    private final SecurityPlaneProperties securityPlaneProperties;

    public EventTimeZoneRegistrar(SecurityPlaneProperties securityPlaneProperties) {
        this.securityPlaneProperties = securityPlaneProperties;
    }

    @Override
    public void afterPropertiesSet() {
        String timeZone = securityPlaneProperties.getContext() != null
                ? securityPlaneProperties.getContext().getTimeZone()
                : null;
        EventTimeZone.set(StringUtils.hasText(timeZone) ? ZoneId.of(timeZone.trim()) : null);
    }

    @Override
    public void destroy() {
        EventTimeZone.set(null);
    }
}
