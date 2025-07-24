package com.ahamo.dummy.demo2.auth.repository;

import com.ahamo.dummy.demo2.auth.entity.Role;
import com.ahamo.dummy.demo2.auth.entity.User;
import com.ahamo.dummy.demo2.auth.entity.UserRole;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@ActiveProfiles("test")
class UserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserRepository userRepository;

    @Test
    void findByEmail_Success() {
        User user = User.builder()
                .email("test@example.com")
                .passwordHash("hashedPassword")
                .isVerified(true)
                .isActive(true)
                .build();
        entityManager.persistAndFlush(user);

        Optional<User> found = userRepository.findByEmail("test@example.com");

        assertTrue(found.isPresent());
        assertEquals("test@example.com", found.get().getEmail());
    }

    @Test
    void findByContractNumber_Success() {
        User user = User.builder()
                .email("test@example.com")
                .contractNumber("1234567890")
                .passwordHash("hashedPassword")
                .isVerified(true)
                .isActive(true)
                .build();
        entityManager.persistAndFlush(user);

        Optional<User> found = userRepository.findByContractNumber("1234567890");

        assertTrue(found.isPresent());
        assertEquals("1234567890", found.get().getContractNumber());
    }

    @Test
    void existsByEmail_True() {
        User user = User.builder()
                .email("test@example.com")
                .passwordHash("hashedPassword")
                .isVerified(true)
                .isActive(true)
                .build();
        entityManager.persistAndFlush(user);

        boolean exists = userRepository.existsByEmail("test@example.com");

        assertTrue(exists);
    }

    @Test
    void existsByEmail_False() {
        boolean exists = userRepository.existsByEmail("nonexistent@example.com");

        assertFalse(exists);
    }

    @Test
    void findByEmailWithRoles_Success() {
        Role role = Role.builder()
                .name(Role.RoleName.USER)
                .description("User role")
                .build();
        entityManager.persistAndFlush(role);

        User user = User.builder()
                .email("test@example.com")
                .passwordHash("hashedPassword")
                .isVerified(true)
                .isActive(true)
                .build();
        entityManager.persistAndFlush(user);

        UserRole userRole = UserRole.builder()
                .user(user)
                .role(role)
                .build();
        entityManager.persistAndFlush(userRole);

        user.setUserRoles(Set.of(userRole));
        entityManager.persistAndFlush(user);

        Optional<User> found = userRepository.findByEmailWithRoles("test@example.com");

        assertTrue(found.isPresent());
        assertEquals(1, found.get().getUserRoles().size());
    }
}
