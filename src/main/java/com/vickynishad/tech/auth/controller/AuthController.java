package com.vickynishad.tech.auth.controller;

import com.vickynishad.tech.auth.web.AuthContracts;
import com.vickynishad.tech.auth.web.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthContracts.AuthenticationEnvelope> register(@Valid @RequestBody AuthContracts.RegisterCommand cmd) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(cmd));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthContracts.AuthenticationEnvelope> login(@Valid @RequestBody AuthContracts.LoginCommand cmd) {
        return ResponseEntity.ok(authService.login(cmd));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthContracts.AuthenticationEnvelope> refresh(@Valid @RequestBody AuthContracts.RefreshTokenCommand cmd) {
        return ResponseEntity.ok(authService.refresh(cmd));
    }
}

