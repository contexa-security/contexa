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
package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.domain.dto.GroupDto;
import io.contexa.contexaiam.domain.dto.RoleMetadataDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.GroupRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Controller
@RequestMapping("/admin/groups")
@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class GroupController {

    private final GroupService groupService;
    private final RoleService roleService;
    private final ModelMapper modelMapper;
    private final GroupRepository groupRepository;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String getGroups(@RequestParam(required = false) String keyword,
                            @PageableDefault(size = 15, sort = "id", direction = Sort.Direction.DESC) Pageable pageable,
                            Model model) {
        Page<Group> groupPage;
        if (keyword != null && !keyword.isBlank()) {
            groupPage = groupRepository.findByNameContainingIgnoreCaseOrDescriptionContainingIgnoreCase(keyword, keyword, pageable);
        } else {
            groupPage = groupRepository.findAll(pageable);
        }
        Page<GroupDto> dtoPage = groupPage.map(group -> {
            GroupDto dto = modelMapper.map(group, GroupDto.class);
            dto.setRoleCount(group.getGroupRoles() != null ? group.getGroupRoles().size() : 0);
            dto.setUserCount(group.getUserGroups() != null ? group.getUserGroups().size() : 0);
            return dto;
        });
        model.addAttribute("groups", dtoPage.getContent());
        model.addAttribute("page", dtoPage);
        model.addAttribute("keyword", keyword);
        return "admin/groups";
    }
    @GetMapping("/register")
    public String registerGroupForm(Model model) {
        GroupDto groupDto = new GroupDto();
        groupDto.setEnabled(true);
        model.addAttribute("group", groupDto);
        model.addAttribute("roleList", roleService.getRoles());
        model.addAttribute("selectedRoleIds", new HashSet<Long>());
        return "admin/groupdetails";
    }

    @PostMapping
    @Transactional(transactionManager = "contexaTransactionManager")
    public String createGroup(@ModelAttribute("group") GroupDto groupDto,
                              @RequestParam(value = "selectedRoleIds", required = false) List<Long> selectedRoleIds,
                              RedirectAttributes ra) {
        try {
            Group group = modelMapper.map(groupDto, Group.class);
            groupService.createGroup(group, selectedRoleIds); 

            ra.addFlashAttribute("message", msg("msg.group.created", group.getName()));
                    } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.warn("Failed to create group: {}", e.getMessage());
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("msg.group.create.error", e.getMessage()));
            log.error("Error creating group", e);
        }
        return "redirect:/admin/groups";
    }

    @GetMapping("/{id}")
    public String getGroupDetails(@PathVariable Long id, Model model, RedirectAttributes ra) {
        try {
            Group group = groupService.getGroup(id)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid group ID: " + id));
            List<Role> roles = roleService.getRoles();

            GroupDto groupDto = modelMapper.map(group, GroupDto.class);
            List<Long> selectedRoleIds = group.getGroupRoles() == null ? List.of() :
                    group.getGroupRoles().stream()
                            .filter(gr -> gr.getRole() != null && gr.getRole().getId() != null)
                            .map(gr -> gr.getRole().getId())
                            .collect(Collectors.toList());
            groupDto.setSelectedRoleIds(selectedRoleIds);

            List<RoleMetadataDto> roleListDtos = roles.stream()
                    .map(role -> modelMapper.map(role, RoleMetadataDto.class))
                    .collect(Collectors.toList());

            model.addAttribute("group", groupDto);
            model.addAttribute("roleList", roleListDtos);
            model.addAttribute("selectedRoleIds", selectedRoleIds);
            return "admin/groupdetails";
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.warn("Failed to load group details: {}", e.getMessage());
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("msg.group.load.failed", e.getMessage()));
            log.error("Error loading group details for ID: {}", id, e);
        }
        return "redirect:/admin/groups";
    }

    @PostMapping("/{id}/edit")
    @Transactional(transactionManager = "contexaTransactionManager")
    public String updateGroup(@PathVariable Long id, @ModelAttribute("group") GroupDto groupDto,
                              @RequestParam(value = "selectedRoleIds", required = false) List<Long> selectedRoleIds,
                              RedirectAttributes ra) {
        try {
            groupDto.setId(id); 
            Group group = modelMapper.map(groupDto, Group.class);
            groupService.updateGroup(group, selectedRoleIds); 

            ra.addFlashAttribute("message", msg("msg.group.updated", group.getName()));
                    } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.warn("Failed to update group: {}", e.getMessage());
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("msg.group.update.error", e.getMessage()));
            log.error("Error updating group", e);
        }
        return "redirect:/admin/groups";
    }

    @PostMapping("/delete/{id}")
    @Transactional(transactionManager = "contexaTransactionManager")
    public String deleteGroup(@PathVariable Long id, RedirectAttributes ra) {
        try {
            groupService.deleteGroup(id);
            ra.addFlashAttribute("message", msg("msg.group.deleted", id));
                    } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("msg.group.delete.error", e.getMessage()));
            log.error("Error deleting group ID: {}", id, e);
        }
        return "redirect:/admin/groups";
    }
}
