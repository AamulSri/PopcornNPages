package com.popcornNpages.AuthService.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.popcornNpages.AuthService.model.User;



@Repository
public interface UserRepository extends JpaRepository<User,Integer> {
 
    User findByEmail(String email);
} 
