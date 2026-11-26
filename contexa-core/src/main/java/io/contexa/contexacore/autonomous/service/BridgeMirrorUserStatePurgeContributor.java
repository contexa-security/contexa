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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Deletes the bridge mirror users of a deleted account. The security bridge mirrors an authenticated principal into a
 * bridge-managed user whose external subject is the principal's name, with a bridge profile; left behind, that row
 * keeps the deleted account's subject and profile in the user table after the account is gone. Mirrors are removed
 * the way an account is (its role permissions and bridge profile first) without announcing another account deletion.
 */
public class BridgeMirrorUserStatePurgeContributor implements UserStatePurgeContributor {

    private final ObjectProvider<UserRepository> users;
    private final ObjectProvider<BridgeUserProfileRepository> profiles;
    private final ObjectProvider<UserRolePermissionRepository> rolePermissions;
    private final ObjectProvider<PlatformTransactionManager> transactionManager;

    public BridgeMirrorUserStatePurgeContributor(ObjectProvider<UserRepository> users,
                                                 ObjectProvider<BridgeUserProfileRepository> profiles,
                                                 ObjectProvider<UserRolePermissionRepository> rolePermissions,
                                                 ObjectProvider<PlatformTransactionManager> transactionManager) {
        this.users = users;
        this.profiles = profiles;
        this.rolePermissions = rolePermissions;
        this.transactionManager = transactionManager;
    }

    @Override
    public String name() {
        return "bridge-mirror-users";
    }

    @Override
    public void purge(String userId) {
        UserRepository userRepository = users.getIfAvailable();
        PlatformTransactionManager transactions = transactionManager.getIfAvailable();
        if (userRepository == null || transactions == null || userId == null || userId.isBlank()) {
            return;
        }
        BridgeUserProfileRepository profileRepository = profiles.getIfAvailable();
        UserRolePermissionRepository rolePermissionRepository = rolePermissions.getIfAvailable();
        // The purge runs after the deletion committed (UserAccountDeletionListener, AFTER_COMMIT), where joining the
        // finished transaction would run the deletes without one (CF-21): the mirrors go in a transaction of their own.
        TransactionTemplate template = new TransactionTemplate(transactions);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        template.executeWithoutResult(status -> {
            for (Users mirror : mirrorsOf(userRepository, userId)) {
                Long id = mirror.getId();
                if (rolePermissionRepository != null) {
                    rolePermissionRepository.deleteByUserId(id);
                }
                if (profileRepository != null && profileRepository.existsById(id)) {
                    profileRepository.deleteById(id);
                }
                userRepository.deleteById(id);
            }
        });
    }

    /**
     * The mirrors of the principal: those kept under its decision key (bridge v2 B5-1, decision 7), then those an older
     * version kept under the name as given; a mirror found both ways is one.
     */
    private static List<Users> mirrorsOf(UserRepository userRepository, String userId) {
        String decisionKey = ZeroTrustUserKey.of(userId);
        Map<Long, Users> mirrors = new LinkedHashMap<>();
        for (Users mirror : userRepository.findByExternalSubjectIdAndBridgeManagedTrue(decisionKey)) {
            mirrors.putIfAbsent(mirror.getId(), mirror);
        }
        if (!decisionKey.equals(userId)) {
            for (Users mirror : userRepository.findByExternalSubjectIdAndBridgeManagedTrue(userId)) {
                mirrors.putIfAbsent(mirror.getId(), mirror);
            }
        }
        return new ArrayList<>(mirrors.values());
    }
}
