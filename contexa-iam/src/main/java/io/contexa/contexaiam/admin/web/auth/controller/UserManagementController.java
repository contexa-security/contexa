package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.domain.dto.UserDto;
import io.contexa.contexaiam.domain.dto.UserListDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Slf4j
@RequestMapping("/admin/users")
@RequiredArgsConstructor
public class UserManagementController {

	private final UserManagementService userManagementService;
	private final RoleService roleService;
	private final GroupService groupService;

	@GetMapping
	public String getUsers(Model model) {
		List<UserListDto> users = userManagementService.getUsers();
		model.addAttribute("users", users);
		return "admin/users";
	}

	// 새 사용자 등록 폼
	@GetMapping("/new")
	public String showCreateForm(Model model) {
		UserDto userDto = new UserDto();
		List<Role> roleList = roleService.getRolesWithoutExpression();
		List<Group> groupList = groupService.getAllGroups();

		model.addAttribute("user", userDto);
		model.addAttribute("roleList", roleList);
		model.addAttribute("groupList", groupList);
		model.addAttribute("selectedGroupIds", List.of());

		return "admin/userdetails";
	}

	// 사용자 수정 폼
	@GetMapping("/{id}")
	public String getUser(@PathVariable Long id, Model model) {
		UserDto userDto = userManagementService.getUser(id);
		List<Role> roleList = roleService.getRolesWithoutExpression();
		List<Group> groupList = groupService.getAllGroups();

		List<Long> selectedGroupIds = userDto.getSelectedGroupIds();
		if (selectedGroupIds == null) {
			selectedGroupIds = List.of();
		}

		model.addAttribute("user", userDto);
		model.addAttribute("roleList", roleList);
		model.addAttribute("groupList", groupList);
		model.addAttribute("selectedGroupIds", selectedGroupIds);

		return "admin/userdetails";
	}

	// 사용자 수정 처리 - PUT 메서드 지원
	@PutMapping("/{id}")
	public String updateUser(@PathVariable Long id,
							 @ModelAttribute("user") UserDto userDto,
							 @RequestParam(value = "selectedGroupIds", required = false) List<Long> selectedGroupIds,
							 RedirectAttributes ra) {
		try {
			userDto.setId(id);
			userDto.setSelectedGroupIds(selectedGroupIds);
			userManagementService.modifyUser(userDto);
			ra.addFlashAttribute("message", "사용자 '" + userDto.getUsername() + "' 정보가 성공적으로 수정되었습니다!");
			log.info("User {} modified.", userDto.getUsername());
		} catch (Exception e) {
			log.error("Error modifying user: ", e);
			ra.addFlashAttribute("errorMessage", "사용자 수정 중 오류가 발생했습니다: " + e.getMessage());
			return "redirect:/admin/users/" + id;
		}
		return "redirect:/admin/users";
	}

	// POST 메서드로도 수정 처리 (HTML form 호환성)
	@PostMapping("/{id}")
	public String updateUserPost(@PathVariable Long id,
								 @ModelAttribute("user") UserDto userDto,
								 @RequestParam(value = "selectedGroupIds", required = false) List<Long> selectedGroupIds,
								 RedirectAttributes ra) {
		return updateUser(id, userDto, selectedGroupIds, ra);
	}

	// 사용자 삭제
	@DeleteMapping("/{id}")
	public String removeUser(@PathVariable Long id, RedirectAttributes ra) {
		try {
			userManagementService.deleteUser(id);
			ra.addFlashAttribute("message", "사용자 (ID: " + id + ")가 성공적으로 삭제되었습니다!");
			log.info("User ID {} deleted.", id);
		} catch (Exception e) {
			log.error("Error deleting user: ", e);
			ra.addFlashAttribute("errorMessage", "사용자 삭제 중 오류가 발생했습니다: " + e.getMessage());
		}
		return "redirect:/admin/users";
	}

	// GET 메서드로도 삭제 처리 (링크 호환성)
	@GetMapping("/delete/{id}")
	public String removeUserGet(@PathVariable Long id, RedirectAttributes ra) {
		return removeUser(id, ra);
	}
}