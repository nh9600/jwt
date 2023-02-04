package com.sky.jwt.service;

import com.sky.jwt.Repository.UserRepository;
import com.sky.jwt.dto.UserDto;
import com.sky.jwt.entity.Authority;
import com.sky.jwt.entity.User;
import com.sky.jwt.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public UserDto signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        /**
         * 권한 정보가 없으면 만듦
         */
        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        /**
         * 유저정보와 권한정보를 저장
         */
        return UserDto.from(userRepository.save(user));
    }

    /**
     *
     * 유저네임에 해당하는 유저&권한 정보를 가져오는 메소드
     */
    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    /**
     * securityContext에 저장된 유저네임만 가져오는 메소드
     */
    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername);
                        //.orElseThrow(() -> new NotFoundMemberException("Member not found"))
    }
}
