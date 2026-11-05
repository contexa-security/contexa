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
package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexacommon.security.UserAuthoritiesChangedEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;

/**
 * A service whose changes reach what accounts may do. It says so with {@link #authoritiesChanged()} in the transaction of
 * the change: the listeners run after the commit, so a change that fails or rolls back reaches nobody.
 */
abstract class AccountAuthoritiesService implements ApplicationEventPublisherAware {

    private ApplicationEventPublisher eventPublisher;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    protected void authoritiesChanged() {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(new UserAuthoritiesChangedEvent());
        }
    }
}
