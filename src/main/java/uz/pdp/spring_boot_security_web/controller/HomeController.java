package uz.pdp.spring_boot_security_web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class HomeController {

    @GetMapping()
    public String home(){
        return "register";
    }


    @GetMapping("/cabinet")
    public String cabinet(){
        return "CABINET";
    }
}
