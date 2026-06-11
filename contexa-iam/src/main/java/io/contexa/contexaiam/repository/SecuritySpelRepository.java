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
package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.SecuritySpel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface SecuritySpelRepository extends JpaRepository<SecuritySpel, Long> {

    @Query("SELECT s FROM SecuritySpel s WHERE " +
            "(:pattern IS NULL " +
            "OR LOWER(s.name) LIKE :pattern " +
            "OR LOWER(s.description) LIKE :pattern)")
    List<SecuritySpel> search(@Param("pattern") String pattern);
}
