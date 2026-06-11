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

import com.querydsl.core.BooleanBuilder;
import com.querydsl.jpa.impl.JPAQueryFactory;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.QManagedResource;
import io.contexa.contexacommon.entity.QPermission;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class ManagedResourceRepositoryCustomImpl implements ManagedResourceRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public Page<ManagedResource> findByCriteria(ResourceSearchCriteria criteria, Pageable pageable) {
        QManagedResource resource = QManagedResource.managedResource;
        QPermission permission = QPermission.permission;

        BooleanBuilder whereClause = createWhereClause(criteria, resource);

        List<ManagedResource> content = queryFactory
                .selectFrom(resource)
                .leftJoin(resource.permission, permission).fetchJoin()
                .where(whereClause)
                .offset(pageable.getOffset()) 
                .limit(pageable.getPageSize())  
                .orderBy(resource.createdAt.desc()) 
                .fetch();

        Long total = queryFactory
                .select(resource.count())
                .from(resource)
                .where(whereClause)
                .fetchOne();

        return new PageImpl<>(content, pageable, total != null ? total : 0);
    }

    private BooleanBuilder createWhereClause(ResourceSearchCriteria search, QManagedResource resource) {
        BooleanBuilder builder = new BooleanBuilder();

        if (search.getStatus() != null) {
            builder.and(resource.status.eq(search.getStatus()));
        } else {
            builder.and(resource.status.ne(ManagedResource.Status.EXCLUDED));
        }

        if (StringUtils.hasText(search.getKeyword())) {
            builder.and(
                    resource.friendlyName.containsIgnoreCase(search.getKeyword())
                            .or(resource.resourceIdentifier.containsIgnoreCase(search.getKeyword()))
                            .or(resource.description.containsIgnoreCase(search.getKeyword()))
            );
        }

        if (StringUtils.hasText(search.getServiceOwner())) {
            builder.and(resource.serviceOwner.eq(search.getServiceOwner()));
        }

        return builder;
    }
}
