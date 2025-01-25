package ru.kata.spring.boot_security.demo.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.kata.spring.boot_security.demo.models.User;
import java.util.Optional;

@Repository
public interface UsersRepository extends JpaRepository<User, Integer> {
    @Query("Select u from User u left join fetch u.roles where u.name=:name")
    User findByName(String name);
    @Query("Select u from User u left join fetch u.roles where u.email=:email")
    User findByEmail(String email);
}
