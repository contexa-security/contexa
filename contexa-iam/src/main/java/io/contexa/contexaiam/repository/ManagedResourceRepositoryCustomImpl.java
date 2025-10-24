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

/**
 * [최종 디버깅 및 완성]
 * 사유: QuerydslRepositorySupport를 사용하지 않는 현재 구조에서 존재하지 않는 getQuerydsl()을
 *      호출하는 치명적인 오류를 수정합니다. JPAQueryFactory를 사용하여 직접 offset, limit을
 *      적용하는 방식으로 페이징 로직을 올바르게 구현합니다.
 */
@Repository
@RequiredArgsConstructor
public class ManagedResourceRepositoryCustomImpl implements ManagedResourceRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public Page<ManagedResource> findByCriteria(ResourceSearchCriteria criteria, Pageable pageable) {
        QManagedResource resource = QManagedResource.managedResource;
        QPermission permission = QPermission.permission;

        BooleanBuilder whereClause = createWhereClause(criteria, resource);

        // Content 조회 쿼리 (fetch join 포함)
        List<ManagedResource> content = queryFactory
                .selectFrom(resource)
                .leftJoin(resource.permission, permission).fetchJoin()
                .where(whereClause)
                .offset(pageable.getOffset()) // [핵심 수정] getQuerydsl() 대신 직접 offset 적용
                .limit(pageable.getPageSize())  // [핵심 수정] getQuerydsl() 대신 직접 limit 적용
                .orderBy(resource.createdAt.desc()) // 정렬 조건 추가
                .fetch();

        // Count 조회 쿼리 (동일한 WHERE 조건 사용)
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