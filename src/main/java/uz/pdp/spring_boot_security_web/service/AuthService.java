package uz.pdp.spring_boot_security_web.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import uz.pdp.spring_boot_security_web.entity.UserEntity;
import uz.pdp.spring_boot_security_web.repository.UserRepository;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public boolean login(String username, String password) {
        Optional<UserEntity> optionalUserEntity = userRepository.findByUsername(username);
        if (optionalUserEntity.isEmpty()) {
            return false;
        }
        UserEntity userEntity = optionalUserEntity.get();
        if (passwordEncoder.matches(password, userEntity.getPassword())) {
            this.authenticate(userEntity);
            return true;
        }
        return false;
    }

    private void authenticate(UserEntity userEntity) {
        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        userEntity.getUsername(),
                        null,
                        userEntity.getAuthorities()
                );

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

}
