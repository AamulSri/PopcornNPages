package com.popcornNpages.popcornNpages.model;

import jakarta.persistence.Column;
import org.hibernate.annotations.CreationTimestamp;
import com.popcornNpages.popcornNpages.model.enums.Role;
import org.hibernate.annotations.UpdateTimestamp;
import java.time.LocalDateTime;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;


@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "user")
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    @Enumerated(EnumType.STRING)
    private Role role;
    private String firstName;
    private String lastName;
    @Column(unique = true)
    private String email;

    @Size(min = 8, message ="Password must be of minimum 8 Characters")
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).*$",
    message = "Must contain: 1 uppercase, 1 lowercase, 1 number, 1 special character")
    private String password;

    @CreationTimestamp
    private LocalDateTime creationDate;
    @UpdateTimestamp
    private LocalDateTime lastUpdated;
    
}
