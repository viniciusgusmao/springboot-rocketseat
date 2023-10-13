package br.com.vgusmao.todolist.Filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.vgusmao.todolist.task.ITaskRepository;
import br.com.vgusmao.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

  @Autowired
  IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
        var servletPath = request.getServletPath();
        if (servletPath.startsWith("/tasks")){
          // pegar a autenticação - usuário e senha
          var auth = request.getHeader("Authorization");
          var encoded = auth.substring("Basic".length()).trim();
          byte[] authDecoded = Base64.getDecoder().decode(encoded);
          var authString = new String(authDecoded);
          String[] array = authString.split(":");
          String username = array[0];
          String password = array[1];

          // validar o usuário
          var user = this.userRepository.findByUsername(username);
          if (user == null){
            response.sendError(401);
          } else {
            // validar a senha
            var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
            if (passwordVerify.verified){
              request.setAttribute("idUser", user.getId());
              filterChain.doFilter(request, response);
            } else {
              response.sendError(401);
            }
          }
        } else {
          filterChain.doFilter(request, response);
        }
    
  }
  
}
