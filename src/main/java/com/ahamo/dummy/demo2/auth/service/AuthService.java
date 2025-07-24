package com.ahamo.dummy.demo2.auth.service;

import com.ahamo.dummy.demo2.auth.dto.LoginRequest;
import com.ahamo.dummy.demo2.auth.dto.ContractLoginRequest;
import com.ahamo.dummy.demo2.auth.dto.RefreshTokenRequest;
import com.ahamo.dummy.demo2.auth.dto.AuthResponse;
import com.ahamo.dummy.demo2.auth.entity.RefreshToken;
import com.ahamo.dummy.demo2.auth.entity.User;
import com.ahamo.dummy.demo2.auth.exception.AuthenticationException;
import com.ahamo.dummy.demo2.auth.exception.TokenRefreshException;
import com.ahamo.dummy.demo2.auth.repository.RefreshTokenRepository;
import com.ahamo.dummy.demo2.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RateLimitService rateLimitService;

    @Transactional
    public AuthResponse authenticateUser(LoginRequest loginRequest) {
        String email = loginRequest.getEmail();
        
        if (rateLimitService.isBlocked(email)) {
            throw new AuthenticationException("Account temporarily locked due to too many failed attempts");
        }

        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new AuthenticationException("Invalid credentials"));

            if (user.isAccountLocked()) {
                throw new AuthenticationException("Account is locked");
            }

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, loginRequest.getPassword())
            );

            resetFailedAttempts(user);
            
            String jwt = jwtService.generateJwtToken(authentication);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

            log.info("User {} successfully authenticated", email);
            
            return AuthResponse.builder()
                    .accessToken(jwt)
                    .refreshToken(refreshToken.getToken())
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .build();

        } catch (BadCredentialsException e) {
            handleFailedLogin(email);
            throw new AuthenticationException("Invalid credentials");
        }
    }

    @Transactional
    public AuthResponse authenticateByContract(ContractLoginRequest contractLoginRequest) {
        String contractNumber = contractLoginRequest.getContractNumber();
        
        if (rateLimitService.isBlocked(contractNumber)) {
            throw new AuthenticationException("Account temporarily locked due to too many failed attempts");
        }

        try {
            User user = userRepository.findByContractNumberWithRoles(contractNumber)
                    .orElseThrow(() -> new AuthenticationException("Invalid contract number"));

            if (user.isAccountLocked()) {
                throw new AuthenticationException("Account is locked");
            }

            if (!passwordEncoder.matches(contractLoginRequest.getPassword(), user.getPasswordHash())) {
                handleFailedLogin(contractNumber);
                throw new AuthenticationException("Invalid credentials");
            }

            resetFailedAttempts(user);
            
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    user.getEmail(), null, null);

            String jwt = jwtService.generateJwtToken(authentication);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

            log.info("User with contract {} successfully authenticated", contractNumber);
            
            return AuthResponse.builder()
                    .accessToken(jwt)
                    .refreshToken(refreshToken.getToken())
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .build();

        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            handleFailedLogin(contractNumber);
            throw new AuthenticationException("Invalid credentials");
        }
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtService.generateRefreshToken(user.getEmail());
                    return AuthResponse.builder()
                            .accessToken(token)
                            .refreshToken(requestRefreshToken)
                            .tokenType("Bearer")
                            .expiresIn(3600L)
                            .build();
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken, "Refresh token is not in database!"));
    }

    private void handleFailedLogin(String identifier) {
        User user = userRepository.findByEmail(identifier)
                .or(() -> userRepository.findByContractNumber(identifier))
                .orElse(null);

        if (user != null) {
            user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
            
            if (user.getFailedLoginAttempts() >= 5) {
                user.setLockedUntil(LocalDateTime.now().plusMinutes(5));
                log.warn("Account {} locked due to too many failed attempts", identifier);
            }
            
            userRepository.save(user);
        }
        
        rateLimitService.recordFailedAttempt(identifier);
    }

    private void resetFailedAttempts(User user) {
        if (user.getFailedLoginAttempts() > 0) {
            user.setFailedLoginAttempts(0);
            user.setLockedUntil(null);
            userRepository.save(user);
        }
    }
}
