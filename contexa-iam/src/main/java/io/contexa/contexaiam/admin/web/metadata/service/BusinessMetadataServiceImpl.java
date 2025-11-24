package io.contexa.contexaiam.admin.web.metadata.service;

import io.contexa.contexaiam.domain.dto.*;
import io.contexa.contexaiam.repository.BusinessActionRepository;
import io.contexa.contexaiam.repository.BusinessResourceRepository;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexacommon.entity.business.BusinessAction;
import io.contexa.contexacommon.entity.business.BusinessResource;
import io.contexa.contexacommon.entity.business.BusinessResourceAction;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Transactional(readOnly = true)
public class BusinessMetadataServiceImpl implements BusinessMetadataService {

    private final BusinessResourceRepository businessResourceRepository;
    private final BusinessActionRepository businessActionRepository;
    private final ConditionTemplateRepository conditionTemplateRepository;
    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final RoleService roleService;
    private final ModelMapper modelMapper;

    @Override
    public List<BusinessResourceDto> getAllBusinessResources() {
        return businessResourceRepository.findAll().stream()
                .map(action -> modelMapper.map(action, BusinessResourceDto.class))
                .toList();
    }

    @Override
    public List<BusinessActionDto> getAllBusinessActions() {
        return businessActionRepository.findAll().stream()
                .map(action -> modelMapper.map(action, BusinessActionDto.class))
                .toList();
    }

    @Override
    public List<BusinessAction> getActionsForResource(Long businessResourceId) {
        if (businessResourceId == null) {
            return Collections.emptyList();
        }

        Optional<BusinessResource> resourceOptional = businessResourceRepository.findById(businessResourceId);

        // [핵심 수정] 조인 엔티티(BusinessResourceAction)에서 실제 BusinessAction을 추출하여 리스트로 반환
        return resourceOptional.map(businessResource -> businessResource.getAvailableActions().stream()
                .map(BusinessResourceAction::getBusinessAction)
                .collect(Collectors.toList())).orElseGet(Collections::emptyList);
    }

    @Override
    public List<ConditionTemplate> getAllConditionTemplates() {
        return conditionTemplateRepository.findAll();
    }

    @Override
    public List<UserMetadataDto> getAllUsersForPolicy() {
        return userRepository.findAll().stream()
                .map(user -> modelMapper.map(user, UserMetadataDto.class))
                .collect(Collectors.toList());
    }

    @Override
    public List<GroupMetadataDto> getAllGroupsForPolicy() {
        return groupRepository.findAll().stream()
                .map(group -> modelMapper.map(group, GroupMetadataDto.class))
                .collect(Collectors.toList());
    }

    @Override
    public Map<String, Object> getAllUsersAndGroups() {
        return Map.of(
                "users", getAllUsersForPolicy(),
                "groups", getAllGroupsForPolicy()
        );
    }

    @Override
    public List<RoleMetadataDto> getAllRoles() {
        return roleService.getRoles().stream()
                .map(role -> modelMapper.map(role, RoleMetadataDto.class))
                .collect(Collectors.toList());
    }


}
