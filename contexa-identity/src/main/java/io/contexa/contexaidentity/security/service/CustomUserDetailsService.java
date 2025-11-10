package io.contexa.contexaidentity.security.service;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaidentity.domain.dto.UserDto;
import io.contexa.contexaidentity.security.filter.MfaGrantedAuthority;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user = userRepository.findByUsernameWithGroupsRolesAndPermissions(username) // 새로운 쿼리 사용
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username));

        UserDto userDto = modelMapper.map(user, UserDto.class);
        List<MfaGrantedAuthority> authorities = user.getRoleNames().stream().map(MfaGrantedAuthority::new)
                .toList();

        userDto.setAuthorities(authorities);
        return new CustomUserDetails(userDto);
    }
}
