package com.vickynishad.tech.auth.web;


import com.vickynishad.tech.auth.entity.Role;
import com.vickynishad.tech.auth.entity.User;
import com.vickynishad.tech.auth.repository.UserRepository;
import com.vickynishad.tech.auth.security.JwtService;
import com.vickynishad.tech.auth.token.RefreshTokenService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       RefreshTokenService refreshTokenService,
                       AuthenticationManager authenticationManager,
                       UserDetailsService userDetailsService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }

    @Transactional
    public AuthContracts.AuthenticationEnvelope register(AuthContracts.RegisterCommand cmd) {
        if (userRepository.existsByEmail(cmd.email())) {
            throw new IllegalArgumentException("User with this email already exists");
        }

        User user = User.builder()
                .email(cmd.email())
                .password(passwordEncoder.encode(cmd.password()))
                .role(Role.ROLE_USER)
                .build();
        userRepository.save(user);

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getEmail());
        String accessToken = jwtService.generateAccessToken(userDetails, Map.of("role", user.getRole().name()));
        String refreshToken = refreshTokenService.createRefreshToken(user, null);

        return new AuthContracts.AuthenticationEnvelope(accessToken, refreshToken, jwtService.getAccessTokenExpirationSeconds());
    }

    @Transactional
    public AuthContracts.AuthenticationEnvelope login(AuthContracts.LoginCommand cmd) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(cmd.email(), cmd.password()));

        User user = userRepository.findByEmail(cmd.email()).orElseThrow();
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getEmail());

        String accessToken = jwtService.generateAccessToken(userDetails, Map.of("role", user.getRole().name()));
        String refreshToken = refreshTokenService.createRefreshToken(user, null);

        return new AuthContracts.AuthenticationEnvelope(accessToken, refreshToken, jwtService.getAccessTokenExpirationSeconds());
    }

    @Transactional
    public AuthContracts.AuthenticationEnvelope refresh(AuthContracts.RefreshTokenCommand cmd) {
        RefreshTokenService.RotateResult rotateResult = refreshTokenService.rotate(cmd.refreshToken());
        UserDetails userDetails = userDetailsService.loadUserByUsername(rotateResult.user().getEmail());

        String accessToken = jwtService.generateAccessToken(userDetails, Map.of("role", rotateResult.user().getRole().name()));

        return new AuthContracts.AuthenticationEnvelope(accessToken, rotateResult.newRefreshToken(), jwtService.getAccessTokenExpirationSeconds());
    }
}