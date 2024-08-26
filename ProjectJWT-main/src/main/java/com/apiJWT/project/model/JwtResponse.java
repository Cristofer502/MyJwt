package com.apiJWT.project.model;

public class JwtResponse {

    private String jwtToken;

    public JwtResponse(String token) {
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public void setJwtToken(String jwtToken) {
        this.jwtToken = jwtToken;
    }
}
