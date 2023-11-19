package com.bolsadeideas.springboot.app.auth.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.FlashMap;
import org.springframework.web.servlet.support.SessionFlashMapManager;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
@Component
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        SessionFlashMapManager flashMapManager = new SessionFlashMapManager();
        FlashMap flashMap = new FlashMap();
        flashMap.put("success", "Hola ".concat(authentication.getName()).concat(", haz iniciado sesion con éxito"));
        flashMapManager.saveOutputFlashMap(flashMap, request, response);
        if(authentication != null){
            logger.info("El usuario ".concat(authentication.getName()).concat(" ha iniciado sesion con exito"));
        }
        super.onAuthenticationSuccess(request, response, authentication);
    }
   
}
