package edu.acu.wip.cas;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author hgm02a
 */
public class RedirectUriServlet extends HttpServlet {

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    String redirectUri = req.getParameter("redirect_uri");
    if (redirectUri == null) {
      super.doGet(req, resp);
      return;
    }
    resp.sendRedirect(redirectUri);
  }
  
}
