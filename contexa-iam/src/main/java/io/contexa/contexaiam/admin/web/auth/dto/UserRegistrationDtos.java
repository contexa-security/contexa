package io.contexa.contexaiam.admin.web.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.contexacommon.domain.UserDto;
import lombok.Data;

import java.io.Serializable;
import java.util.List;

public final class UserRegistrationDtos {

    private UserRegistrationDtos() {
    }

    @Data
    public static class UserRegistrationRequest {
        private String username;
        private String password;
        private String name;
        private String email;
        private String phone;
        private String department;
        private String position;
        private String locale;
        private String timezone;

        public UserDto toUserDto() {
            UserDto dto = new UserDto();
            dto.setUsername(username);
            dto.setPassword(password);
            dto.setName(name);
            dto.setEmail(email);
            dto.setPhone(phone);
            dto.setDepartment(department);
            dto.setPosition(position);
            dto.setLocale(locale);
            dto.setTimezone(timezone);
            return dto;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record UserRegistrationErrorResponse(
            String error,
            List<String> violations
    ) implements Serializable {
        public static UserRegistrationErrorResponse error(String error) {
            return new UserRegistrationErrorResponse(error, null);
        }

        public static UserRegistrationErrorResponse violations(String error, List<String> violations) {
            return new UserRegistrationErrorResponse(error, violations);
        }
    }
}
