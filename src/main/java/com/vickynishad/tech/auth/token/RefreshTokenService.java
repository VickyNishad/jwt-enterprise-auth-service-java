package com.vickynishad.tech.auth.token;


import com.vickynishad.tech.auth.entity.RefreshToken;
import com.vickynishad.tech.auth.entity.User;
import com.vickynishad.tech.auth.exception.SecurityBreachException;
import com.vickynishad.tech.auth.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository repository;
    private final long refreshTokenExpirationMs;

    public RefreshTokenService(
            RefreshTokenRepository repository,
            @Value("${security.jwt.refresh-token-expiration-ms}") long refreshTokenExpirationMs) {
        this.repository = repository;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
    }

    @Transactional
    public String createRefreshToken(User user, String familyId) {
        String rawToken = generateSecureRandomString();
        String tokenHash = hashToken(rawToken);

        RefreshToken token = RefreshToken.builder()
                .tokenHash(tokenHash)
                .user(user)
                .familyId(familyId != null ? familyId : UUID.randomUUID().toString())
                .expiresAt(Instant.now().plusMillis(refreshTokenExpirationMs))
                .build();
        repository.save(token);
        return rawToken;
    }

    @Transactional
    public RotateResult rotate(String rawToken) {
        String tokenHash = hashToken(rawToken);
        RefreshToken storedToken = repository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new SecurityBreachException("Refresh token not found"));

        // Reuse Detection: A revoked token being presented implies token compromise
        if (storedToken.isRevoked()) {
            repository.revokeFamily(storedToken.getFamilyId());
            throw new SecurityBreachException("Compromised token family detected. All active sessions terminated.");
        }

        if (storedToken.getExpiresAt().isBefore(Instant.now())) {
            throw new SecurityBreachException("Refresh token has expired");
        }

        // Revoke the old token
        storedToken.setRevoked(true);
        repository.save(storedToken);

        // Issue a child token within the same family chain
        String newRawToken = createRefreshToken(storedToken.getUser(), storedToken.getFamilyId());
        return new RotateResult(storedToken.getUser(), newRawToken);
    }

    public record RotateResult(User user, String newRefreshToken) {}

    private String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(encodedhash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm unavailable", e);
        }
    }

    private String generateSecureRandomString() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}