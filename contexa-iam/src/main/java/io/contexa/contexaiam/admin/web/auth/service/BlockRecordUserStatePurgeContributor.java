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

import io.contexa.contexacore.autonomous.service.UserStatePurgeContributor;
import org.springframework.beans.factory.ObjectProvider;

import java.util.function.Supplier;

/**
 * Closes the blocks recorded for a deleted account. The record is the second copy of a BLOCK and is written back to the
 * decision store while it holds one in force, so a record left behind would block the deleted account again, and any
 * later account created with the same name.
 */
public class BlockRecordUserStatePurgeContributor implements UserStatePurgeContributor {

    private final Supplier<BlockedUserService> blockedUsers;

    public BlockRecordUserStatePurgeContributor(ObjectProvider<BlockedUserService> blockedUsers) {
        this((Supplier<BlockedUserService>) blockedUsers::getIfAvailable);
    }

    /** Asked at the time of a deletion, and may answer nothing. */
    public BlockRecordUserStatePurgeContributor(Supplier<BlockedUserService> blockedUsers) {
        this.blockedUsers = blockedUsers;
    }

    @Override
    public String name() {
        return "block-record";
    }

    @Override
    public void purge(String userId) {
        BlockedUserService service = blockedUsers.get();
        if (service != null) {
            service.resolveBlocksOfDeletedAccount(userId);
        }
    }
}
