package uz.pdp.spring_boot_security_web.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import uz.pdp.spring_boot_security_web.model.dto.UserLoginDTO;
import uz.pdp.spring_boot_security_web.service.AuthService;

@Controller
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @GetMapping("/login")
    public String login(){
        return "login";
    }

    @PostMapping("/login")
    public String login(
            @ModelAttribute UserLoginDTO userLoginDTO
    ){
        boolean isSuccess = authService.login(userLoginDTO.getUsername(), userLoginDTO.getPassword());
        if (isSuccess){
            return "redirect:/cabinet";
        }
        return "redirect:/auth/login";

    }
}
