package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.dto.UserDto;
import io.contexa.contexaiam.domain.dto.UserListDto;

import java.util.List;

public interface UserManagementService {

    void modifyUser(UserDto userDto);
    List<UserListDto> getUsers();
    UserDto getUser(Long id);
    void deleteUser(Long idx);

}
