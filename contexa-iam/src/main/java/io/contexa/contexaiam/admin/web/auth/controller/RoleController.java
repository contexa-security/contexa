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

import io.contexa.contexaiam.admin.web.auth.dto.AffectedPolicyDtos.AffectedPoliciesResponse;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.dto.RoleDto;
import io.contexa.contexacommon.entity.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Controller
@RequestMapping("/contexa/admin/roles")
@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class RoleController {

	private final RoleService roleService;
	private final PermissionService permissionService;
	private final ModelMapper modelMapper;
	private final MessageSource messageSource;

	private String msg(String key, Object... args) {
		return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
	}

	@GetMapping
	public String getRoles(@RequestParam(required = false) String keyword,
						   @PageableDefault(size = 15, sort = "id", direction = Sort.Direction.DESC) Pageable pageable,
						   Model model) {
		Page<Role> rolePage = roleService.searchRoles(keyword, pageable);
		Page<RoleDto> dtoPage = rolePage.map(role -> {
			RoleDto dto = modelMapper.map(role, RoleDto.class);
			dto.setPermissionCount(role.getRolePermissions() != null ? role.getRolePermissions().size() : 0);
			return dto;
		});
		model.addAttribute("roles", dtoPage.getContent());
		model.addAttribute("page", dtoPage);
		model.addAttribute("keyword", keyword);
		return "contexa/admin/roles";
	}

	@GetMapping("/register")
	public String registerRoleForm(Model model) {
		RoleDto roleDto = new RoleDto();
		roleDto.setEnabled(true);
		model.addAttribute("role", roleDto);
		model.addAttribute("permissionList", permissionService.getAllPermissions());
		model.addAttribute("selectedPermissionIds", new ArrayList<Long>());
		return "contexa/admin/rolesdetails";
	}

	@PostMapping
	@Transactional(transactionManager = "contexaTransactionManager")
	public String createRole(@ModelAttribute("role") RoleDto roleDto, RedirectAttributes ra) {
		Role role = modelMapper.map(roleDto, Role.class);
		roleService.createRole(role, roleDto.getPermissionIds());
		ra.addFlashAttribute("message", msg("msg.role.created"));
		return "redirect:/contexa/admin/roles";
	}

	@GetMapping("/{id}")
	public String getRoleDetails(@PathVariable Long id, Model model) {
		Role role = roleService.getRole(id);
		RoleDto roleDto = modelMapper.map(role, RoleDto.class);
		List<Long> selectedPermissionIds = role.getRolePermissions().stream().map(rp -> rp.getPermission().getId()).toList();

		List<PermissionDto> permissionList = permissionService.getAllPermissions().stream()
				.map(p -> modelMapper.map(p, PermissionDto.class))
				.toList();

		model.addAttribute("role", roleDto);
		model.addAttribute("permissionList", permissionList);
		model.addAttribute("selectedPermissionIds", selectedPermissionIds);
		return "contexa/admin/rolesdetails";
	}

	@PostMapping("/{id}/edit")
	@Transactional(transactionManager = "contexaTransactionManager")
	public String updateRole(@PathVariable Long id, @ModelAttribute("role") RoleDto roleDto, RedirectAttributes ra) {
		roleDto.setId(id);
		Role role = modelMapper.map(roleDto, Role.class);
		roleService.updateRole(role, roleDto.getPermissionIds());
		ra.addFlashAttribute("message", msg("msg.role.updated"));
		return "redirect:/contexa/admin/roles";
	}

	@GetMapping("/api/{id}/affected-policies")
	@ResponseBody
	public ResponseEntity<AffectedPoliciesResponse> getAffectedPolicies(@PathVariable Long id) {
		return roleService.getAffectedPolicies(id)
				.map(ResponseEntity::ok)
				.orElseGet(() -> ResponseEntity.notFound().build());
	}

	@PostMapping("/delete/{id}")
	@Transactional(transactionManager = "contexaTransactionManager")
	public String deleteRole(@PathVariable Long id, RedirectAttributes ra) {
		try {
			roleService.deleteRole(id);
			ra.addFlashAttribute("message", msg("msg.role.deleted"));
		} catch (Exception e) {
			ra.addFlashAttribute("errorMessage", e.getMessage());
		}
		return "redirect:/contexa/admin/roles";
	}
}
