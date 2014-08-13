package edu.acu.wip.cas;

import com.google.inject.Singleton;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl;
import org.jasig.cas.client.authentication.GatewayResolver;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.validation.Assertion;

import static org.jasig.cas.client.util.CommonUtils.assertNotNull;
import static org.jasig.cas.client.util.CommonUtils.isNotBlank;
import static org.jasig.cas.client.util.CommonUtils.safeGetParameter;
import static org.jasig.cas.client.authentication.AuthenticationFilter.CONST_CAS_ASSERTION;

/**
 *
 * @author hgm02a
 */
@Singleton
public class NoRedirectCasFilter extends AbstractCasFilter {

    /**
     * The URL to the CAS Server login.
     */
    private String casServerLoginUrl;
    /**
     * Whether to send the renew request or not.
     */
    private boolean renew = false;
    /**
     * Whether to send the gateway request or not.
     */
    private boolean gateway = false;
    private GatewayResolver gatewayStorage = new DefaultGatewayResolverImpl();
    private String page = null;
    private String script = null;

    @Override
    protected void initInternal(final FilterConfig filterConfig) throws ServletException {
        if (!isIgnoreInitConfiguration()) {
            super.initInternal(filterConfig);
            this.page = getPropertyFromInitParams(filterConfig, "page", null);
            logger.trace("Loaded loginUrl parameter: " + this.page);
            this.script = getPropertyFromInitParams(filterConfig, "script", null);
            logger.trace("Loaded loginUrl parameter: " + this.script);

            setCasServerLoginUrl(getPropertyFromInitParams(filterConfig, "casServerLoginUrl", null));
            logger.trace("Loaded CasServerLoginUrl parameter: " + this.casServerLoginUrl);
            setRenew(parseBoolean(getPropertyFromInitParams(filterConfig, "renew", "false")));
            logger.trace("Loaded renew parameter: " + this.renew);
            setGateway(parseBoolean(getPropertyFromInitParams(filterConfig, "gateway", "false")));
            logger.trace("Loaded gateway parameter: " + this.gateway);

            final String gatewayStorageClass = getPropertyFromInitParams(filterConfig, "gatewayStorageClass", null);

            if (gatewayStorageClass != null) {
                try {
                    this.gatewayStorage = (GatewayResolver) Class.forName(gatewayStorageClass).newInstance();
                } catch (final ClassNotFoundException | IllegalAccessException | InstantiationException e) {
                    logger.error("Exception creating new instance of gatewayStorageClass ({})", gatewayStorageClass, e);
                    throw new ServletException(e);
                }
            }
        }
    }

    @Override
    public void init() {
        super.init();
        assertNotNull(this.page, "page cannot be null.");
        assertNotNull(this.script, "script cannot be null.");
    }

    @Override
    public final void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse, final FilterChain filterChain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;
        final HttpSession session = request.getSession(false);
        final String serviceUrl = constructServiceUrl(request, response);
        final Assertion assertion = session != null ? (Assertion) session.getAttribute(CONST_CAS_ASSERTION) : null;

        if (assertion != null) {
            filterChain.doFilter(request, response);
            return;
        }

        final String ticket = safeGetParameter(request, getArtifactParameterName());
        final boolean wasGatewayed = this.gatewayStorage.hasGatewayedAlready(request, serviceUrl);

        if (isNotBlank(ticket) || wasGatewayed) {
            filterChain.doFilter(request, response);
            return;
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.addHeader("WWW-Authenticate", "FORM " + page);
    }

    public final void setRenew(final boolean renew) {
        this.renew = renew;
    }

    public final void setGateway(final boolean gateway) {
        this.gateway = gateway;
    }

    public final void setCasServerLoginUrl(final String casServerLoginUrl) {
        this.casServerLoginUrl = casServerLoginUrl;
    }

    public final void setGatewayStorage(final GatewayResolver gatewayStorage) {
        this.gatewayStorage = gatewayStorage;
    }
}