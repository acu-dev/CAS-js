package edu.acu.wip.cas;

import java.io.IOException;
import java.net.URLDecoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HashServlet extends HttpServlet {
    private static final Logger logger = LoggerFactory
            .getLogger(HashServlet.class);

    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        this.doPost(req, resp);
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String url = req.getParameter("url");
        url = url == null ? "" : url;
        logger.debug(String.format("url: %s", url));
        resp.sendRedirect(URLDecoder.decode(url, "UTF-8"));
    }

    private static final long serialVersionUID = 3194047774437245973L;

}