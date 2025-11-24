package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleHierarchyService;
import io.contexa.contexaiam.domain.dto.RoleDetailDto;
import io.contexa.contexaiam.domain.dto.RoleHierarchyDto;
import io.contexa.contexaiam.domain.dto.RoleMetadataDto;
import io.contexa.contexaiam.domain.dto.*;
import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.GroupRole;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.*;
import java.util.stream.Collectors;

@RequestMapping("/admin/role-hierarchies")
@RequiredArgsConstructor
@Slf4j
public class RoleHierarchyController {

    private final RoleHierarchyService roleHierarchyService;
    private final ModelMapper modelMapper;
    private final RoleService roleService;
    private final GroupService groupService; // 추가: 그룹 정보 조회용

    @GetMapping
    public String getRoleHierarchies(Model model) {
        List<RoleHierarchyEntity> hierarchies = roleHierarchyService.getAllRoleHierarchies();
        List<RoleHierarchyDto> roleHierarchyList = hierarchies.stream().map(roleHierarchy -> {
            return modelMapper.map(roleHierarchy, RoleHierarchyDto.class);
        }).toList();
        model.addAttribute("hierarchies", roleHierarchyList);
        log.info("Displaying role hierarchies list. Total: {}", roleHierarchyList.size());
        return "admin/role-hierarchies";
    }

    @GetMapping("/register")
    public String registerRoleHierarchyForm(Model model) {
        model.addAttribute("hierarchy", new RoleHierarchyDto());
        prepareHierarchyFormModel(model, new ArrayList<>());
        return "admin/role-hierarchy-details";
    }

    @PostMapping
    public String createRoleHierarchy(@ModelAttribute("hierarchy") RoleHierarchyDto hierarchyDto, RedirectAttributes ra) {
        try {
            RoleHierarchyEntity entity = modelMapper.map(hierarchyDto, RoleHierarchyEntity.class);
            roleHierarchyService.createRoleHierarchy(entity);
            ra.addFlashAttribute("message", "역할 계층이 성공적으로 생성되었습니다!");
            log.info("Role hierarchy created: {}", entity.getHierarchyString());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("error", e.getMessage());
            return "redirect:/admin/role-hierarchies/register";
        }
        return "redirect:/admin/role-hierarchies";
    }

    @GetMapping("/{id}")
    public String roleHierarchyDetails(@PathVariable Long id, Model model) {
        try {
            RoleHierarchyEntity entity = roleHierarchyService.getRoleHierarchy(id)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid RoleHierarchy ID: " + id));

            RoleHierarchyDto dto = modelMapper.map(entity, RoleHierarchyDto.class);

            // 계층 문자열 디버깅
            String hierarchyString = entity.getHierarchyString();
            log.info("Raw hierarchy string from DB: [{}]", hierarchyString);

            // \n 문자열을 실제 개행문자로 변환
            if (hierarchyString != null && hierarchyString.contains("\\n")) {
                hierarchyString = hierarchyString.replace("\\n", "\n");
                log.info("Converted hierarchy string: [{}]", hierarchyString);
            }

            List<RoleHierarchyDto.HierarchyPair> pairs = new ArrayList<>();
            if (hierarchyString != null && !hierarchyString.trim().isEmpty()) {
                // 실제 개행문자로 분리
                String[] lines = hierarchyString.split("\n");

                for (String line : lines) {
                    line = line.trim();
                    if (line.contains(">")) {
                        String[] parts = line.split("\\s*>\\s*"); // > 양쪽 공백 제거
                        if (parts.length == 2) {
                            String parent = parts[0].trim();
                            String child = parts[1].trim();

                            pairs.add(new RoleHierarchyDto.HierarchyPair(parent, child));
                            log.debug("Parsed pair: {} > {}", parent, child);
                        }
                    }
                }
            }

            dto.setHierarchyPairs(pairs);
            model.addAttribute("hierarchy", dto);
            prepareHierarchyFormModel(model, pairs);

            log.info("Role hierarchy details loaded - ID: {}, Valid pairs: {}", id, pairs.size());

        } catch (Exception e) {
            log.error("Error loading role hierarchy details for ID: {}", id, e);
            model.addAttribute("error", "역할 계층 정보를 불러오는 중 오류가 발생했습니다.");
            return "redirect:/admin/role-hierarchies";
        }

        return "admin/role-hierarchy-details";
    }

    @PostMapping("/{id}/edit")
    public String updateRoleHierarchy(@PathVariable Long id, @ModelAttribute("hierarchy") RoleHierarchyDto hierarchyDto, RedirectAttributes ra) {
        try {
            hierarchyDto.setId(id);
            RoleHierarchyEntity entity = modelMapper.map(hierarchyDto, RoleHierarchyEntity.class);
            roleHierarchyService.updateRoleHierarchy(entity);
            ra.addFlashAttribute("message", "역할 계층이 성공적으로 업데이트되었습니다!");
            log.info("Role hierarchy updated: {}", entity.getHierarchyString());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("error", e.getMessage());
            return "redirect:/admin/role-hierarchies/" + id;
        }
        return "redirect:/admin/role-hierarchies";
    }

    @GetMapping("/delete/{id}")
    public String deleteRoleHierarchy(@PathVariable Long id, RedirectAttributes ra) {
        roleHierarchyService.deleteRoleHierarchy(id);
        ra.addFlashAttribute("message", "역할 계층 (ID: " + id + ")이 성공적으로 삭제되었습니다!");
        log.info("Role hierarchy deleted: ID {}", id);
        return "redirect:/admin/role-hierarchies";
    }

    @PostMapping("/{id}/activate")
    public String activateRoleHierarchy(@PathVariable Long id, RedirectAttributes ra) {
        roleHierarchyService.activateRoleHierarchy(id);
        ra.addFlashAttribute("message", "역할 계층 (ID: " + id + ")이 활성화되었습니다!");
        log.info("Role hierarchy activated: ID {}", id);
        return "redirect:/admin/role-hierarchies";
    }

    /**
     * 역할 계층 폼에 필요한 모델 데이터를 준비합니다.
     * - 모든 역할을 그룹별로 구조화
     * - 각 역할의 권한 정보 포함
     */
    private void prepareHierarchyFormModel(Model model, List<RoleHierarchyDto.HierarchyPair> existingPairs) {
        try {
            // 모든 그룹과 역할 정보를 조회 (N+1 문제 방지를 위해 fetch join 사용)
            List<Group> allGroups = groupService.getAllGroups();

            // 그룹별 역할 정보를 구조화
            List<GroupWithRolesDto> groupsWithRoles = allGroups.stream()
                    .map(group -> {
                        GroupWithRolesDto gwrDto = new GroupWithRolesDto();
                        gwrDto.setGroupId(group.getId());
                        gwrDto.setGroupName(group.getName());
                        gwrDto.setGroupDescription(group.getDescription());

                        List<RoleDetailDto> roleDetails = group.getGroupRoles().stream()
                                .map(GroupRole::getRole)
                                .filter(role -> role != null && !"Y".equals(role.getIsExpression())) // 표현식 역할 제외
                                .map(role -> {
                                    RoleDetailDto rdDto = new RoleDetailDto();
                                    rdDto.setRoleId(role.getId());
                                    rdDto.setRoleName(role.getRoleName());
                                    rdDto.setRoleDesc(role.getRoleDesc() != null ? role.getRoleDesc() : role.getRoleName());

                                    // 권한 정보 매핑
                                    List<String> permissions = role.getRolePermissions().stream()
                                            .filter(rp -> rp.getPermission() != null)
                                            .map(rp -> rp.getPermission().getFriendlyName())
                                            .filter(name -> name != null)
                                            .sorted()
                                            .collect(Collectors.toList());
                                    rdDto.setPermissions(permissions);

                                    return rdDto;
                                })
                                .collect(Collectors.toList());

                        gwrDto.setRoles(roleDetails);
                        return gwrDto;
                    })
                    .filter(gwrDto -> !gwrDto.getRoles().isEmpty()) // 역할이 없는 그룹 제외
                    .collect(Collectors.toList());

            // 그룹에 속하지 않은 역할들 (혹시 있다면)
            List<RoleMetadataDto> ungroupedRoles = roleService.getRolesWithoutExpression().stream()
                    .filter(role -> allGroups.stream()
                            .noneMatch(group -> group.getGroupRoles().stream()
                                    .anyMatch(gr -> gr.getRole() != null && gr.getRole().getId().equals(role.getId()))))
                    .map(role -> modelMapper.map(role, RoleMetadataDto.class))
                    .collect(Collectors.toList());

            model.addAttribute("groupsWithRoles", groupsWithRoles);
            model.addAttribute("ungroupedRoles", ungroupedRoles);
            model.addAttribute("hierarchyPairs", existingPairs);

            // 모든 역할의 간단한 목록 (호환성 유지)
            List<RoleMetadataDto> allRoles = roleService.getRolesWithoutExpression().stream()
                    .map(role -> modelMapper.map(role, RoleMetadataDto.class))
                    .collect(Collectors.toList());
            model.addAttribute("allRoles", allRoles);

            log.debug("Prepared hierarchy form model - Groups: {}, Ungrouped roles: {}",
                    groupsWithRoles.size(), ungroupedRoles.size());

        } catch (Exception e) {
            log.error("Error preparing hierarchy form model", e);
            model.addAttribute("groupsWithRoles", new ArrayList<>());
            model.addAttribute("ungroupedRoles", new ArrayList<>());
            model.addAttribute("allRoles", new ArrayList<>());
        }
    }
}
