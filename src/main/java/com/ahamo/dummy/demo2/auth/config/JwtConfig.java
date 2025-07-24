package com.ahamo.dummy.demo2.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtConfig {
    
    private String secret;
    private long accessTokenExpiration;
    private long refreshTokenExpiration;
    
}
