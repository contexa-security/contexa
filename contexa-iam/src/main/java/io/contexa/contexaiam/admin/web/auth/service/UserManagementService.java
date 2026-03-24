package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexaiam.domain.dto.UserListDto;

import java.util.List;

public interface UserManagementService {

    void createUser(UserDto userDto);
    void modifyUser(UserDto userDto);
    List<UserListDto> getUsers();
    UserDto getUser(Long id);
    void deleteUser(Long idx);

}
