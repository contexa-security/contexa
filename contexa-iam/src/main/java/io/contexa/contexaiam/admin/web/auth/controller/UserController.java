package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.auth.dto.UserRegistrationDtos.UserRegistrationErrorResponse;
import io.contexa.contexaiam.admin.web.auth.dto.UserRegistrationDtos.UserRegistrationRequest;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;

import org.springframework.stereotype.Controller;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final MessageSource messageSource;
    private final SystemSettingsService systemSettingsService;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping("/register")
    public String registerPage(Model model) {
        if (!systemSettingsService.getSettings().isRegistrationEnabled()) {
            model.addAttribute("registrationDisabled", true);
        }
        return "register";
    }

    @PostMapping("/api/register")
    @ResponseBody
    public ResponseEntity<Serializable> processRegister(@RequestBody UserRegistrationRequest userDto) {

        if (!systemSettingsService.getSettings().isRegistrationEnabled()) {
            return ResponseEntity.<Serializable>badRequest()
                    .body(UserRegistrationErrorResponse.error(msg("msg.registration.disabled")));
        }

        if (userRepository.findByUsername(userDto.getUsername()).isPresent()) {
            return ResponseEntity.<Serializable>badRequest()
                    .body(UserRegistrationErrorResponse.error(msg("msg.user.username.exists")));
        }

        List<String> violations = passwordPolicyService.validatePassword(userDto.getPassword());
        if (!violations.isEmpty()) {
            return ResponseEntity.<Serializable>badRequest()
                    .body(UserRegistrationErrorResponse.violations(
                            msg("msg.user.password.policy.violation"),
                            violations));
        }

        Users users = modelMapper.map(userDto.toUserDto(), Users.class);
        users.setPassword(passwordEncoder.encode(users.getPassword()));
        users.setMfaEnabled(true);
        users.setEnabled(true);
        users.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(users);

        return ResponseEntity.<Serializable>ok().body("success");
    }

    @GetMapping("/users")
    public String usersPage(Model model) {
        return "users";
    }

    @GetMapping("/api/users")
    @ResponseBody
    public ResponseEntity<List<UserDto>> users() {
        List<UserDto> users = userRepository.findAll().stream()
                .map(user -> modelMapper.map(user, UserDto.class))
                .toList();
        return ResponseEntity.ok().body(users);
    }

}
