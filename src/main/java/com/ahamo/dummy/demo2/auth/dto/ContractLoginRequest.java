package com.ahamo.dummy.demo2.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ContractLoginRequest {
    
    @NotBlank(message = "Contract number is required")
    @Pattern(regexp = "^[0-9]{10}$", message = "Contract number must be 10 digits")
    private String contractNumber;
    
    @NotBlank(message = "Password is required")
    @Size(min = 6, max = 100, message = "Password must be between 6 and 100 characters")
    private String password;
}
