package in.gskitchen.jwtauth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TheController {

    @GetMapping("/hello")
    public CustomUser welcomeUser(){
        return new CustomUser("User1", 11);
    }
}
