package com.ahamo.dummy.demo2.auth.service;

import com.ahamo.dummy.demo2.auth.config.JwtConfig;
import com.ahamo.dummy.demo2.auth.security.UserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @Mock
    private JwtConfig jwtConfig;

    @Mock
    private Authentication authentication;

    @InjectMocks
    private JwtService jwtService;

    private UserPrincipal userPrincipal;

    @BeforeEach
    void setUp() {
        userPrincipal = new UserPrincipal(1L, "test@example.com", "test@example.com", "password", Collections.emptyList());
    }

    @Test
    void generateJwtToken_Success() {
        when(jwtConfig.getSecret()).thenReturn("dGVzdFNlY3JldEtleUZvckpXVFRva2VuVGVzdGluZ1B1cnBvc2VzMTIzNDU2Nzg5MFRoaXNJc0FWZXJ5TG9uZ1NlY3JldEtleUZvclRlc3RpbmdQdXJwb3Nlc09ubHk=");
        when(jwtConfig.getAccessTokenExpiration()).thenReturn(3600000L);
        when(authentication.getPrincipal()).thenReturn(userPrincipal);

        String token = jwtService.generateJwtToken(authentication);

        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void generateRefreshToken_Success() {
        when(jwtConfig.getSecret()).thenReturn("dGVzdFNlY3JldEtleUZvckpXVFRva2VuVGVzdGluZ1B1cnBvc2VzMTIzNDU2Nzg5MFRoaXNJc0FWZXJ5TG9uZ1NlY3JldEtleUZvclRlc3RpbmdQdXJwb3Nlc09ubHk=");
        when(jwtConfig.getRefreshTokenExpiration()).thenReturn(86400000L);

        String token = jwtService.generateRefreshToken("test@example.com");

        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void getUsernameFromJwtToken_Success() {
        when(jwtConfig.getSecret()).thenReturn("dGVzdFNlY3JldEtleUZvckpXVFRva2VuVGVzdGluZ1B1cnBvc2VzMTIzNDU2Nzg5MFRoaXNJc0FWZXJ5TG9uZ1NlY3JldEtleUZvclRlc3RpbmdQdXJwb3Nlc09ubHk=");
        when(jwtConfig.getAccessTokenExpiration()).thenReturn(3600000L);
        when(authentication.getPrincipal()).thenReturn(userPrincipal);

        String token = jwtService.generateJwtToken(authentication);
        String username = jwtService.getUsernameFromJwtToken(token);

        assertEquals("test@example.com", username);
    }

    @Test
    void validateJwtToken_ValidToken() {
        when(jwtConfig.getSecret()).thenReturn("dGVzdFNlY3JldEtleUZvckpXVFRva2VuVGVzdGluZ1B1cnBvc2VzMTIzNDU2Nzg5MFRoaXNJc0FWZXJ5TG9uZ1NlY3JldEtleUZvclRlc3RpbmdQdXJwb3Nlc09ubHk=");
        when(jwtConfig.getAccessTokenExpiration()).thenReturn(3600000L);
        when(authentication.getPrincipal()).thenReturn(userPrincipal);

        String token = jwtService.generateJwtToken(authentication);
        boolean isValid = jwtService.validateJwtToken(token);

        assertTrue(isValid);
    }

    @Test
    void validateJwtToken_InvalidToken() {
        when(jwtConfig.getSecret()).thenReturn("dGVzdFNlY3JldEtleUZvckpXVFRva2VuVGVzdGluZ1B1cnBvc2VzMTIzNDU2Nzg5MFRoaXNJc0FWZXJ5TG9uZ1NlY3JldEtleUZvclRlc3RpbmdQdXJwb3Nlc09ubHk=");
        String invalidToken = "invalid.jwt.token";

        boolean isValid = jwtService.validateJwtToken(invalidToken);

        assertFalse(isValid);
    }

    @Test
    void validateJwtToken_EmptyToken() {
        when(jwtConfig.getSecret()).thenReturn("dGVzdFNlY3JldEtleUZvckpXVFRva2VuVGVzdGluZ1B1cnBvc2VzMTIzNDU2Nzg5MFRoaXNJc0FWZXJ5TG9uZ1NlY3JldEtleUZvclRlc3RpbmdQdXJwb3Nlc09ubHk=");
        boolean isValid = jwtService.validateJwtToken("");

        assertFalse(isValid);
    }
}
