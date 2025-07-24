package com.ahamo.dummy.demo2.auth.repository;

import com.ahamo.dummy.demo2.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
    
    Optional<User> findByContractNumber(String contractNumber);
    
    Optional<User> findByPhoneNumber(String phoneNumber);
    
    @Query("SELECT u FROM User u LEFT JOIN FETCH u.userRoles ur LEFT JOIN FETCH ur.role WHERE u.email = :email")
    Optional<User> findByEmailWithRoles(@Param("email") String email);
    
    @Query("SELECT u FROM User u LEFT JOIN FETCH u.userRoles ur LEFT JOIN FETCH ur.role WHERE u.contractNumber = :contractNumber")
    Optional<User> findByContractNumberWithRoles(@Param("contractNumber") String contractNumber);
    
    boolean existsByEmail(String email);
    
    boolean existsByContractNumber(String contractNumber);
    
    boolean existsByPhoneNumber(String phoneNumber);
}
