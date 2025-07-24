package com.ahamo.dummy.demo2.auth.service;

import com.ahamo.dummy.demo2.auth.dto.AuthResponse;
import com.ahamo.dummy.demo2.auth.dto.ContractLoginRequest;
import com.ahamo.dummy.demo2.auth.dto.LoginRequest;
import com.ahamo.dummy.demo2.auth.dto.RefreshTokenRequest;
import com.ahamo.dummy.demo2.auth.entity.RefreshToken;
import com.ahamo.dummy.demo2.auth.entity.Role;
import com.ahamo.dummy.demo2.auth.entity.User;
import com.ahamo.dummy.demo2.auth.entity.UserRole;
import com.ahamo.dummy.demo2.auth.exception.AuthenticationException;
import com.ahamo.dummy.demo2.auth.exception.TokenRefreshException;
import com.ahamo.dummy.demo2.auth.repository.RefreshTokenRepository;
import com.ahamo.dummy.demo2.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserRepository userRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private JwtService jwtService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private RateLimitService rateLimitService;

    @InjectMocks
    private AuthService authService;

    private User testUser;
    private LoginRequest loginRequest;
    private ContractLoginRequest contractLoginRequest;
    private RefreshTokenRequest refreshTokenRequest;

    @BeforeEach
    void setUp() {
        Role userRole = Role.builder()
                .id(1L)
                .name(Role.RoleName.USER)
                .description("User role")
                .build();

        UserRole userRoleEntity = UserRole.builder()
                .id(1L)
                .role(userRole)
                .build();

        testUser = User.builder()
                .id(1L)
                .email("test@example.com")
                .contractNumber("1234567890")
                .passwordHash("hashedPassword")
                .isVerified(true)
                .isActive(true)
                .failedLoginAttempts(0)
                .userRoles(Set.of(userRoleEntity))
                .build();

        userRoleEntity.setUser(testUser);

        loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password");

        contractLoginRequest = new ContractLoginRequest();
        contractLoginRequest.setContractNumber("1234567890");
        contractLoginRequest.setPassword("password");

        refreshTokenRequest = new RefreshTokenRequest();
        refreshTokenRequest.setRefreshToken("refresh-token");
    }

    @Test
    void authenticateUser_Success() {
        Authentication authentication = mock(Authentication.class);
        RefreshToken refreshToken = RefreshToken.builder()
                .token("refresh-token")
                .user(testUser)
                .build();

        when(rateLimitService.isBlocked(anyString())).thenReturn(false);
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(jwtService.generateJwtToken(authentication)).thenReturn("jwt-token");
        when(refreshTokenService.createRefreshToken(1L)).thenReturn(refreshToken);

        AuthResponse response = authService.authenticateUser(loginRequest);

        assertNotNull(response);
        assertEquals("jwt-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());
        assertEquals("Bearer", response.getTokenType());
        assertEquals(3600L, response.getExpiresIn());

        verify(userRepository).save(testUser);
        assertEquals(0, testUser.getFailedLoginAttempts());
    }

    @Test
    void authenticateUser_InvalidCredentials() {
        when(rateLimitService.isBlocked(anyString())).thenReturn(false);
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        assertThrows(AuthenticationException.class, () -> authService.authenticateUser(loginRequest));
        verify(rateLimitService).recordFailedAttempt("test@example.com");
    }

    @Test
    void authenticateUser_AccountLocked() {
        testUser.setLockedUntil(LocalDateTime.now().plusMinutes(5));
        when(rateLimitService.isBlocked(anyString())).thenReturn(false);
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

        assertThrows(AuthenticationException.class, () -> authService.authenticateUser(loginRequest));
    }

    @Test
    void authenticateUser_RateLimited() {
        when(rateLimitService.isBlocked("test@example.com")).thenReturn(true);

        assertThrows(AuthenticationException.class, () -> authService.authenticateUser(loginRequest));
    }

    @Test
    void authenticateByContract_Success() {
        RefreshToken refreshToken = RefreshToken.builder()
                .token("refresh-token")
                .user(testUser)
                .build();

        when(rateLimitService.isBlocked(anyString())).thenReturn(false);
        when(userRepository.findByContractNumberWithRoles("1234567890")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("password", "hashedPassword")).thenReturn(true);
        when(jwtService.generateJwtToken(any(Authentication.class))).thenReturn("jwt-token");
        when(refreshTokenService.createRefreshToken(1L)).thenReturn(refreshToken);

        AuthResponse response = authService.authenticateByContract(contractLoginRequest);

        assertNotNull(response);
        assertEquals("jwt-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());
    }

    @Test
    void authenticateByContract_InvalidPassword() {
        when(rateLimitService.isBlocked(anyString())).thenReturn(false);
        when(userRepository.findByContractNumberWithRoles("1234567890")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("password", "hashedPassword")).thenReturn(false);

        assertThrows(AuthenticationException.class, () -> authService.authenticateByContract(contractLoginRequest));
        verify(rateLimitService).recordFailedAttempt("1234567890");
    }

    @Test
    void refreshToken_Success() {
        RefreshToken refreshToken = RefreshToken.builder()
                .token("refresh-token")
                .user(testUser)
                .build();

        when(refreshTokenService.findByToken("refresh-token")).thenReturn(Optional.of(refreshToken));
        when(refreshTokenService.verifyExpiration(refreshToken)).thenReturn(refreshToken);
        when(jwtService.generateRefreshToken("test@example.com")).thenReturn("new-jwt-token");

        AuthResponse response = authService.refreshToken(refreshTokenRequest);

        assertNotNull(response);
        assertEquals("new-jwt-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());
    }

    @Test
    void refreshToken_TokenNotFound() {
        when(refreshTokenService.findByToken("refresh-token")).thenReturn(Optional.empty());

        assertThrows(TokenRefreshException.class, () -> authService.refreshToken(refreshTokenRequest));
    }
}
