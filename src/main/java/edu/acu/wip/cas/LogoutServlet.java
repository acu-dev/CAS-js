package edu.acu.wip.cas;

import com.google.inject.Inject;
import com.google.inject.name.Named;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author hgm02a
 */
public class LogoutServlet extends HttpServlet {
	
	private final String logoutUrl;
	
	@Inject
	public LogoutServlet(@Named("logoutUrl") String logoutUrl) {
		super();
		this.logoutUrl = logoutUrl;
	}

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		if (req.getSession(false) != null) {
			req.getSession(false).invalidate();
		}
		resp.sendRedirect(this.logoutUrl);
  }
  
}
