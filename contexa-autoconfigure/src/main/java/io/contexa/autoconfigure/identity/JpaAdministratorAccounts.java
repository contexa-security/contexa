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

import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.springframework.transaction.support.TransactionTemplate;

/** The administrator seed's accounts through the user and group repositories, in Contexa's JPA transaction. */
final class JpaAdministratorAccounts implements AdministratorAccounts {

    private final UserRepository users;
    private final GroupRepository groups;
    private final TransactionTemplate transactions;

    JpaAdministratorAccounts(UserRepository users, GroupRepository groups, TransactionTemplate transactions) {
        this.users = users;
        this.groups = groups;
        this.transactions = transactions;
    }

    @Override
    public boolean exists(String username, String email) {
        return users.findByUsername(username).isPresent() || users.findFirstByEmailIgnoreCase(email).isPresent();
    }

    @Override
    public long create(String username, String email, String encodedPassword, String name) {
        Users saved = users.save(Users.builder()
                .username(username)
                .email(email)
                .password(encodedPassword)
                .name(name)
                .enabled(true)
                .accountLocked(false)
                .credentialsExpired(false)
                .failedLoginAttempts(0)
                .mfaEnabled(true)
                .bridgeManaged(false)
                .externalAuthOnly(false)
                .build());
        return saved.getId();
    }

    @Override
    public boolean groupExists(long groupId) {
        return groups.existsById(groupId);
    }

    @Override
    public void join(long userId, long groupId) {
        transactions.executeWithoutResult(status -> {
            Users user = users.findById(userId)
                    .orElseThrow(() -> new IllegalStateException("The administrator " + userId + " is gone"));
            Group group = groups.findById(groupId)
                    .orElseThrow(() -> new IllegalStateException("The administrators group " + groupId + " is gone"));
            user.getUserGroups().add(UserGroup.builder().user(user).group(group).build());
        });
    }
}
