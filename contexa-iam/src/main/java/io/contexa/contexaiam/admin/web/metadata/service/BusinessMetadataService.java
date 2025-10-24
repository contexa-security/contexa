package io.contexa.contexaiam.admin.web.metadata.service;

import io.contexa.contexaiam.domain.dto.*;

import io.contexa.contexaiam.domain.dto.*;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexacommon.entity.business.BusinessAction;

import java.util.List;
import java.util.Map;


public interface BusinessMetadataService {

    List<BusinessResourceDto> getAllBusinessResources();

    List<BusinessActionDto> getAllBusinessActions();

    List<BusinessAction> getActionsForResource(Long businessResourceId);

    List<ConditionTemplate> getAllConditionTemplates();

    List<UserMetadataDto> getAllUsersForPolicy();

    List<GroupMetadataDto> getAllGroupsForPolicy();

    Map<String, Object> getAllUsersAndGroups();
    /**
     * [추가] 워크벤치의 '역할 기준 탐색'을 위한 모든 역할 목록을 조회합니다.
     * @return Role 엔티티 리스트
     */
    List<RoleMetadataDto> getAllRoles();
}
