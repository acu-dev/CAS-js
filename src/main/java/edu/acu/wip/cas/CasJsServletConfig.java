package edu.acu.wip.cas;

import java.util.HashMap;
import java.util.Map;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.Filter;

import org.jasig.cas.client.authentication.AuthenticationFilter;
import org.jasig.cas.client.util.HttpServletRequestWrapperFilter;
import org.jasig.cas.client.validation.Cas20ProxyReceivingTicketValidationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Singleton;
import com.google.inject.servlet.GuiceServletContextListener;
import com.google.inject.servlet.ServletModule;

public class CasJsServletConfig extends GuiceServletContextListener {
    private static final Logger logger = LoggerFactory
            .getLogger(CasJsServletConfig.class);

    @Override
    protected Injector getInjector() {
        return Guice.createInjector(new ServletInitModule());
    }

    private class ServletInitModule extends ServletModule {
        @Override
        protected void configureServlets() {
            logger.debug("creating servlets");
            bind(HashServlet.class).in(Singleton.class);
            
            //TODO: this can probably be externalized.
            bind(AuthenticationFilter.class).in(Singleton.class);
            bind(Cas20ProxyReceivingTicketValidationFilter.class).in(Singleton.class);
            bind(HttpServletRequestWrapperFilter.class).in(Singleton.class);
            Map<String, String> filterConfig = new HashMap<String, String>();
            try {
                Context ctx = new InitialContext();
                filterConfig.put("serverName", (String) ctx.lookup("cas/serverName"));
                filterConfig.put("casServerLoginUrl", (String) ctx.lookup("cas/casServerLoginUrl"));
                filterConfig.put("casServerUrlPrefix", (String) ctx.lookup("cas/casServerUrlPrefix"));
            } catch (NamingException e) {
                throw new RuntimeException(e);
            }
            for (Class<? extends Filter> c : new Class[]{AuthenticationFilter.class, Cas20ProxyReceivingTicketValidationFilter.class, HttpServletRequestWrapperFilter.class}) {
                filter("/hash").through(c, filterConfig);
            }
            serve("/hash").with(HashServlet.class);
        }
    }

}
