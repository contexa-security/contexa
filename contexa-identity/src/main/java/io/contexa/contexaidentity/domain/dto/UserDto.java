package io.contexa.contexaidentity.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {
    private Long id;
    private String username;
    private int age;
    private String password;
    private List<String> roles;
    private List<String> permissions;
    private List<Long> selectedGroupIds;
}
