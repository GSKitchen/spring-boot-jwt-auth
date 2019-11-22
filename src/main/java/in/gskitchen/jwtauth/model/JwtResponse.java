package in.gskitchen.jwtauth.model;

import java.io.Serializable;

public class JwtResponse implements Serializable {

    private static final long serialVersionID = -8091879091924046844L;
    private String jwttoken;

    public JwtResponse(String jwttoken) {
        this.jwttoken = jwttoken;
    }

    public String getToken() {
        return this.jwttoken;
    }
}
