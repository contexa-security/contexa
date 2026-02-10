package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexaiam.domain.dto.UserListDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class UserManagementServiceImpl implements UserManagementService {

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapper modelMapper;

    @Transactional
    @Override
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    @Protectable
    public void modifyUser(@ModelAttribute UserDto userDto) {
        Users users = userRepository.findByIdWithGroupsRolesAndPermissions(userDto.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userDto.getId()));

        users.setName(userDto.getName());
        users.setMfaEnabled(userDto.isMfaEnabled());
        if (StringUtils.hasText(userDto.getPassword())) {
            users.setPassword(passwordEncoder.encode(userDto.getPassword()));
        }

        Set<Long> desiredGroupIds = userDto.getSelectedGroupIds() != null
                ? new HashSet<>(userDto.getSelectedGroupIds())
                : new HashSet<>();

        users.getUserGroups().clear();

        for (Long groupId : desiredGroupIds) {
            Group group = groupRepository.findById(groupId)
                    .orElseThrow(() -> new IllegalArgumentException("Group not found with ID: " + groupId));
            UserGroup userGroup = UserGroup.builder()
                    .user(users)
                    .group(group)
                    .build();
            users.getUserGroups().add(userGroup);
        }

        userRepository.save(users);

    }

    @Transactional(readOnly = true)
    @Protectable
    public UserDto getUser(Long id) {
        Users users = userRepository.findByIdWithGroupsRolesAndPermissions(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + id));
        UserDto userDto = modelMapper.map(users, UserDto.class);
        List<String> roles = users.getRoleNames();
        List<String> permissions = users.getPermissionNames();

        userDto.setRoles(roles);
        userDto.setPermissions(permissions);
        if (users.getUserGroups() != null) {
            userDto.setSelectedGroupIds(users.getUserGroups().stream()
                    .map(ug -> ug.getGroup().getId())
                    .collect(Collectors.toList()));
        } else {
            userDto.setSelectedGroupIds(List.of());
        }

        return userDto;
    }

    @Transactional(readOnly = true)
    @Protectable
    public List<UserListDto> getUsers() {
        return userRepository.findAllWithDetails().stream()
                .map(user -> {
                    UserListDto dto = modelMapper.map(user, UserListDto.class);
                    dto.setGroupCount(user.getUserGroups() != null ? user.getUserGroups().size() : 0);
                    long roleCount = user.getRoleNames().stream().distinct().count();
                    dto.setRoleCount((int) roleCount);
                    return dto;
                })
                .toList();
    }

    @Override
    @Transactional
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    @Protectable(ownerField = "id")
    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }
}