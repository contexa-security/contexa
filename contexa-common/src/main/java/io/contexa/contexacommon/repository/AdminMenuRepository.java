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
package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.AdminMenu;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface AdminMenuRepository extends JpaRepository<AdminMenu, Long> {

    @Query("SELECT DISTINCT m FROM AdminMenu m LEFT JOIN FETCH m.roles ORDER BY m.menuOrder ASC")
    List<AdminMenu> findAllWithRolesOrderByMenuOrder();

    List<AdminMenu> findByEnabledTrueOrderByMenuOrderAsc();

    List<AdminMenu> findByParentIdIsNullOrderByMenuOrderAsc();

    List<AdminMenu> findByParentIdOrderByMenuOrderAsc(Long parentId);

    List<AdminMenu> findAllByDataPageOrderByIdAsc(String dataPage);

    @Query("SELECT m.dataPage FROM AdminMenu m WHERE m.dataPage IS NOT NULL GROUP BY m.dataPage HAVING COUNT(m) > 1")
    List<String> findDuplicatedDataPages();

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional(transactionManager = "contexaTransactionManager")
    @Query("UPDATE AdminMenu m SET m.parentId = :newParentId WHERE m.parentId = :oldParentId")
    int reassignChildren(@Param("oldParentId") Long oldParentId, @Param("newParentId") Long newParentId);

    void deleteByParentId(Long parentId);
}
