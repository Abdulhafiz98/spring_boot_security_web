package uz.pdp.spring_boot_security_web.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import uz.pdp.spring_boot_security_web.entity.UserEntity;
import uz.pdp.spring_boot_security_web.model.dto.receive.UserRegisterDTO;
import uz.pdp.spring_boot_security_web.repository.UserRepository;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    public boolean addUser(UserRegisterDTO userRegisterDTO){
        Optional<UserEntity> optionalUserEntity = userRepository.findByUsername(userRegisterDTO.getUsername());
        if (optionalUserEntity.isPresent()){
            return false;
        }
        UserEntity userEntity = UserEntity.of(userRegisterDTO);
        userEntity.setPassword(passwordEncoder.encode(userRegisterDTO.getPassword()));
        userRepository.save(userEntity);
        return true;
    }
}
