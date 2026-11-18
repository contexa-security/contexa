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
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexaiam.admin.web.agent.service.OAuth2AgentProvisioning;

/**
 * The accounts of people the console counts and lists (plan step 9, N3 and N4; K92): the enabled accounts of Contexa's
 * own that are no agent's, a bridge copy of an application's user and an agent's account left out, and what makes one
 * locked now or dormant. The dashboard counts by these conditions and the list of users filters by them, so a number of
 * the dashboard opens the very users it counts. Each condition reads the users table as {@code u}.
 */
public final class AccountsOfPeople {

    /** The accounts of people; its one parameter is {@link #AGENT_MAIL}. */
    public static final String CONDITION = "u.enabled = TRUE AND u.bridge_managed = FALSE "
            + "AND (u.email IS NULL OR LOWER(u.email) NOT LIKE ?)";

    /** The pattern of the addresses of agent accounts. */
    public static final String AGENT_MAIL = "%" + OAuth2AgentProvisioning.ACCOUNT_EMAIL_DOMAIN;

    /** Locked now, by failed sign-ins, the lock not ended; its one parameter is the moment. */
    public static final String LOCKED = "u.account_locked = TRUE AND u.lock_expires_at > ?";

    /**
     * Dormant: the latest sign-in, or the creation of an account that never signed in, before the moment that is its
     * one parameter.
     */
    public static final String DORMANT = "COALESCE(u.last_login_at, u.created_at) < ?";

    /** The days without a sign-in that make an account dormant. */
    public static final int DORMANT_DAYS = 90;

    private AccountsOfPeople() {
    }
}
