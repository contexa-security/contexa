package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.domain.dto.GroupDto;
import io.contexa.contexaiam.domain.dto.RoleMetadataDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RequestMapping("/admin/groups") // 그룹 관리를 위한 공통 경로 설정
@RequiredArgsConstructor
public class GroupController {

    private final GroupService groupService;
    private final RoleService roleService; // RoleService 주입
    private final ModelMapper modelMapper;

    @GetMapping
    public String getGroups(Model model) {
        // 서비스는 엔티티 리스트를 반환
        List<Group> groups = groupService.getAllGroups();
        // [수정] 컨트롤러에서 DTO 리스트로 변환
        List<GroupDto> groupListDtos = groups.stream().map(group -> {
            GroupDto dto = modelMapper.map(group, GroupDto.class);
            dto.setRoleCount(group.getGroupRoles() != null ? group.getGroupRoles().size() : 0);
            dto.setUserCount(group.getUserGroups() != null ? group.getUserGroups().size() : 0);
            return dto;
        }).toList();
        model.addAttribute("groups", groupListDtos);
        return "admin/groups";
    }
    @GetMapping("/register")
    public String registerGroupForm(Model model) {
        model.addAttribute("group", new GroupDto()); // 빈 DTO 객체 전달
        model.addAttribute("roleList", roleService.getRoles()); // 모든 Role 목록
        model.addAttribute("selectedRoleIds", new HashSet<Long>()); // 선택된 역할 ID 목록 초기화
        log.info("Displaying new group registration form.");
        return "admin/groupdetails";
    }

    @PostMapping
    public String createGroup(@ModelAttribute("group") GroupDto groupDto,
                              @RequestParam(value = "selectedRoleIds", required = false) List<Long> selectedRoleIds,
                              RedirectAttributes ra) {
        try {
            Group group = modelMapper.map(groupDto, Group.class);
            groupService.createGroup(group, selectedRoleIds); // Service에 selectedRoleIds 전달

            ra.addFlashAttribute("message", "그룹 '" + group.getName() + "'이 성공적으로 생성되었습니다.");
            log.info("Group created: {}", group.getName());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.warn("Failed to create group: {}", e.getMessage());
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "그룹 생성 중 알 수 없는 오류 발생: " + e.getMessage());
            log.error("Error creating group", e);
        }
        return "redirect:/admin/groups";
    }

    @GetMapping("/{id}")
    public String getGroupDetails(@PathVariable Long id, Model model) {
        // 서비스는 엔티티를 반환
        Group group = groupService.getGroup(id).orElseThrow(() -> new IllegalArgumentException("Invalid group ID: " + id));
        List<Role> roles = roleService.getRoles();

        // [수정] 컨트롤러에서 DTO로 변환
        GroupDto groupDto = modelMapper.map(group, GroupDto.class);
        List<Long> selectedRoleIds = group.getGroupRoles().stream().map(gr -> gr.getRole().getId()).collect(Collectors.toList());
        groupDto.setSelectedRoleIds(selectedRoleIds);

        List<RoleMetadataDto> roleListDtos = roles.stream()
                .map(role -> modelMapper.map(role, RoleMetadataDto.class))
                .collect(Collectors.toList());

        model.addAttribute("group", groupDto);
        model.addAttribute("roleList", roleListDtos);
        model.addAttribute("selectedRoleIds", selectedRoleIds);
        return "admin/groupdetails";
    }

    @PostMapping("/{id}/edit")
    public String updateGroup(@PathVariable Long id, @ModelAttribute("group") GroupDto groupDto,
                              @RequestParam(value = "selectedRoleIds", required = false) List<Long> selectedRoleIds,
                              RedirectAttributes ra) {
        try {
            groupDto.setId(id); // URL 경로에서 받은 ID를 DTO에 설정
            Group group = modelMapper.map(groupDto, Group.class);
            groupService.updateGroup(group, selectedRoleIds); // Service에 selectedRoleIds 전달

            ra.addFlashAttribute("message", "그룹 '" + group.getName() + "'이 성공적으로 업데이트되었습니다!");
            log.info("Group updated: {}", group.getName());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.warn("Failed to update group: {}", e.getMessage());
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "그룹 업데이트 중 알 수 없는 오류 발생: " + e.getMessage());
            log.error("Error updating group", e);
        }
        return "redirect:/admin/groups";
    }

    @GetMapping("/delete/{id}")
    public String deleteGroup(@PathVariable Long id, RedirectAttributes ra) {
        try {
            groupService.deleteGroup(id);
            ra.addFlashAttribute("message", "그룹 (ID: " + id + ")이 성공적으로 삭제되었습니다!");
            log.info("Group deleted: ID {}", id);
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "그룹 삭제 중 오류 발생: " + e.getMessage());
            log.error("Error deleting group ID: {}", id, e);
        }
        return "redirect:/admin/groups";
    }
}
