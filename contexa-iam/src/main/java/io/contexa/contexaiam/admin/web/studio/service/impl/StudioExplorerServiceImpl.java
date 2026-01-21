package io.contexa.contexaiam.admin.web.studio.service.impl;

import io.contexa.contexaiam.admin.web.studio.dto.ExplorerItemDto;
import io.contexa.contexaiam.admin.web.studio.service.StudioExplorerService;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RequiredArgsConstructor
@Transactional(readOnly = true)
public class StudioExplorerServiceImpl implements StudioExplorerService {

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;

    @Override
    public Map<String, List<ExplorerItemDto>> getExplorerItems() {
        List<ExplorerItemDto> users = userRepository.findAll().stream()
                .map(user -> new ExplorerItemDto(
                        user.getId(),
                        Optional.ofNullable(user.getName()).orElse("이름 없음"),
                        "USER",
                        user.getUsername()
                ))
                .toList();

        List<ExplorerItemDto> groups = groupRepository.findAll().stream()
                .map(group -> new ExplorerItemDto(
                        group.getId(),
                        Optional.ofNullable(group.getName()).orElse("이름 없음"),
                        "GROUP",
                        Optional.ofNullable(group.getDescription()).orElse("설명 없음")
                ))
                .toList();

        return Map.of(
                "users", users,
                "groups", groups
        );
    }
}