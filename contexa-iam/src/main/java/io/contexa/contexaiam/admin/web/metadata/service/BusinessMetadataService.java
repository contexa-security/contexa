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
    
    List<RoleMetadataDto> getAllRoles();
}
