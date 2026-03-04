package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.dto.RoleDto;
import io.contexa.contexacommon.entity.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Controller
@RequestMapping("/admin/roles")
@RequiredArgsConstructor
public class RoleController {

	private final RoleService roleService;
	private final PermissionService permissionService;
	private final ModelMapper modelMapper;

	@GetMapping
	public String getRoles(Model model) {
		List<Role> roles = roleService.getRoles();
		List<RoleDto> dtoList = roles.stream().map(role -> {
			RoleDto dto = modelMapper.map(role, RoleDto.class);
			dto.setPermissionCount(role.getRolePermissions() != null ? role.getRolePermissions().size() : 0);
			return dto;
		}).toList();
		model.addAttribute("roles", dtoList);
		return "admin/roles";
	}

	@GetMapping("/register")
	public String registerRoleForm(Model model) {
		model.addAttribute("role", new RoleDto());
		model.addAttribute("permissionList", permissionService.getAllPermissions()); 
		model.addAttribute("selectedPermissionIds", new ArrayList<Long>()); 
		return "admin/rolesdetails";
	}

	@PostMapping
	public String createRole(@ModelAttribute("role") RoleDto roleDto, RedirectAttributes ra) {
		Role role = modelMapper.map(roleDto, Role.class);
		roleService.createRole(role, roleDto.getPermissionIds());
		ra.addFlashAttribute("message", "Role has been successfully created!");
		return "redirect:/admin/roles";
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
		return "admin/rolesdetails";
	}

	@PostMapping("/{id}/edit")
	public String updateRole(@PathVariable Long id, @ModelAttribute("role") RoleDto roleDto, RedirectAttributes ra) {
		roleDto.setId(id); 
		Role role = modelMapper.map(roleDto, Role.class);
		roleService.updateRole(role, roleDto.getPermissionIds());
		ra.addFlashAttribute("message", "Role has been successfully updated!");
		return "redirect:/admin/roles";
	}

	@PostMapping("/delete/{id}")
	public String deleteRole(@PathVariable Long id, RedirectAttributes ra) {
		roleService.deleteRole(id);
		ra.addFlashAttribute("message", "Role has been successfully deleted!");
		return "redirect:/admin/roles";
	}
}
