package com.prashant.auth_service.security;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import com.prashant.auth_service.entity.User;

import java.util.Collection;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Data
public class UserPrincipal implements UserDetails {

    private UUID id;
    private String username;
    private String email;

    @JsonIgnore
    private String password;

    private boolean enabled;
    private boolean accountNonLocked;

    private Collection<? extends GrantedAuthority> authorities;

    public UserPrincipal(UUID id, String username, String email, String password,
                         boolean enabled, boolean accountNonLocked,
                         Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
        this.enabled = enabled;
        this.accountNonLocked = accountNonLocked;
        this.authorities = authorities;
    }

    public static UserPrincipal create(User user) {
        Set<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                .collect(Collectors.toSet());

        // Add permissions as authorities too
        user.getRoles().forEach(role ->
            role.getPermissions().forEach(perm ->
                authorities.add(new SimpleGrantedAuthority(perm.getName()))
            )
        );

        return new UserPrincipal(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPasswordHash(),
                user.isEnabled(),
                user.isAccountNonLocked(),
                authorities
        );
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
