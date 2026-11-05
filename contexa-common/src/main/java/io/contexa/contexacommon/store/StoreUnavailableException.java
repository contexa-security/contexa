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
package io.contexa.contexacommon.store;

import org.springframework.dao.DataAccessResourceFailureException;

/**
 * What a request meets instead of a wait while a store is known to be down. The store's gate has reported the outage
 * once, so this carries no stack trace and those who catch it need not report it again.
 */
public final class StoreUnavailableException extends DataAccessResourceFailureException {

    public StoreUnavailableException(String store) {
        super(store + " is unavailable");
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
