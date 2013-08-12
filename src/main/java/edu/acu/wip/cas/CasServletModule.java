package edu.acu.wip.cas;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.Filter;

import org.jasig.cas.client.authentication.AuthenticationFilter;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.util.HttpServletRequestWrapperFilter;
import org.jasig.cas.client.validation.Cas20ProxyReceivingTicketValidationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Binder;
import com.google.inject.Singleton;
import com.google.inject.servlet.ServletModule;
import org.jasig.cas.client.authentication.Saml11AuthenticationFilter;
import org.jasig.cas.client.validation.Cas10TicketValidationFilter;
import org.jasig.cas.client.validation.Saml11TicketValidationFilter;

/**
 * used to setup ja-sig CAS with Google guice. Typically, this would be called
 * from another ServletModule.
 * <pre>
 * {@code
 * CasServletModule module = new CasServletModule(this.binder());
 * module.protect("/*");
 * }
 * </pre>
 */
public class CasServletModule extends ServletModule {

	private static final Logger logger = LoggerFactory
					.getLogger(CasServletModule.class);
	private String applicationConfigContext;
	private Map<String, String> filterConfig = new HashMap<String, String>();

	/**
	 * @param applicationConfigContext
	 * @see #CasServletModule(String, Binder)
	 */
	public CasServletModule(String applicationConfigContext) {
		this(applicationConfigContext, null);
	}

	/**
	 * Default constructor
	 */
	public CasServletModule() {
		super();
	}

	/**
	 * @see #CasServletModule(String, Binder)
	 */
	public CasServletModule(Binder binder) {
		this(null, binder);
	}

	/**
	 * Class constructor.
	 *
	 * @param applicationContext allows you to configure cas applications referenced by different hosts in the same servlet container
	 * @param binder
	 */
	public CasServletModule(String applicationContext, Binder binder) {
		this();
		this.applicationConfigContext = applicationContext;
		if (binder != null) {
			this.configure(binder);
		}
	}
	private static final List<Class<? extends Filter>> CAS_1_FILTERS = new ArrayList<Class<? extends Filter>>();

	static {
		CAS_1_FILTERS.add(SingleSignOutFilter.class);
		CAS_1_FILTERS.add(AuthenticationFilter.class);
		CAS_1_FILTERS.add(Cas10TicketValidationFilter.class);
		CAS_1_FILTERS.add(HttpServletRequestWrapperFilter.class);
	}
	private static final List<Class<? extends Filter>> CAS_2_FILTERS = new ArrayList<Class<? extends Filter>>();

	static {
		CAS_2_FILTERS.add(SingleSignOutFilter.class);
		CAS_2_FILTERS.add(AuthenticationFilter.class);
		CAS_2_FILTERS.add(Cas20ProxyReceivingTicketValidationFilter.class);
		CAS_2_FILTERS.add(HttpServletRequestWrapperFilter.class);
	}
	private static final List<Class<? extends Filter>> CAS_SAML_FILTERS = new ArrayList<Class<? extends Filter>>();

	static {
		CAS_SAML_FILTERS.add(SingleSignOutFilter.class);
		CAS_SAML_FILTERS.add(Saml11AuthenticationFilter.class);
		CAS_SAML_FILTERS.add(Saml11TicketValidationFilter.class);
		CAS_SAML_FILTERS.add(HttpServletRequestWrapperFilter.class);
	}

	@Override
	protected void configureServlets() {
		logger.info("configuring servlets");

		/* This allows you to have applications hosted at different server urls hosted in the same servlet container */
//		try {
//			Context ctx = new InitialContext();
//			for (String name : new String[]{"serverName",
//																			"casServerLoginUrl", "casServerUrlPrefix"}) {
//				String ctxName = this.applicationConfigContext != null ? String
//								.format("cas/%s/%s", this.applicationConfigContext,
//												name) : String.format("cas/%s", name);
//				try {
//					filterConfig.put(name, (String) ctx.lookup(ctxName));
//				} catch (NamingException e) {
//					if (this.applicationConfigContext == null) {
//						throw e;
//					} else {
//						String topCtxName = String.format("cas/%s", name);
//						logger.info(String.format(
//										"Failed to find %s. Trying %s", ctxName,
//										topCtxName));
//						filterConfig.put(name, (String) ctx.lookup(topCtxName));
//					}
//				}
//			}
//		} catch (NamingException e) {
//			throw new RuntimeException(e);
//		}

		bind(SingleSignOutFilter.class).in(Singleton.class);
		bind(AuthenticationFilter.class).in(Singleton.class);
		bind(Saml11AuthenticationFilter.class).in(Singleton.class);
		bind(Cas20ProxyReceivingTicketValidationFilter.class).in(Singleton.class);
		bind(Cas10TicketValidationFilter.class).in(Singleton.class);
		bind(Saml11TicketValidationFilter.class).in(Singleton.class);
		bind(HttpServletRequestWrapperFilter.class).in(Singleton.class);

		bind(NoRedirectCasFilter.class).in(Singleton.class);
		bind(RedirectUriServlet.class).in(Singleton.class);
		bind(LogoutServlet.class).in(Singleton.class);

		protectSaml("/auth/cas");
		serve("/auth/cas").with(RedirectUriServlet.class);
		serve("/auth/logout").with(LogoutServlet.class);
	}

	/**
	 * protect the urls with CAS.
	 *
	 * @param urlPattern
	 * @param morePatterns
	 */
	public void protect(String urlPattern, String... morePatterns) {
		for (Class<? extends Filter> c : CAS_2_FILTERS) {
			filter(urlPattern, morePatterns).through(c, filterConfig);
		}
	}

	/**
	 * protect the urls with regular expressions with CAS.
	 *
	 * @param regex
	 * @param regexes
	 */
	public void protectRegex(String regex, String... regexes) {
		for (Class<? extends Filter> c : CAS_2_FILTERS) {
			filterRegex(regex, regexes).through(c, filterConfig);
		}
	}

	/**
	 * protect the urls with CAS.
	 *
	 * @param urlPattern
	 * @param morePatterns
	 */
	public void protectSaml(String urlPattern, String... morePatterns) {
		for (Class<? extends Filter> c : CAS_SAML_FILTERS) {
			filter(urlPattern, morePatterns).through(c, filterConfig);
		}
	}

	/**
	 * protect the urls with regular expressions with CAS.
	 *
	 * @param regex
	 * @param regexes
	 */
	public void protectSamlRegex(String regex, String... regexes) {
		for (Class<? extends Filter> c : CAS_SAML_FILTERS) {
			filterRegex(regex, regexes).through(c, filterConfig);
		}
	}

	/**
	 * protect the urls with CAS.
	 *
	 * @param urlPattern
	 * @param morePatterns
	 */
	public void protectNoRedirect(String urlPattern, String... morePatterns) {
		filter(urlPattern, morePatterns).through(HttpServletRequestWrapperFilter.class, filterConfig);
		filter(urlPattern, morePatterns).through(NoRedirectCasFilter.class, filterConfig);
	}

	/**
	 * protect the urls with regular expressions with CAS.
	 *
	 * @param regex
	 * @param regexes
	 */
	public void protectNoRedirectRegex(String regex, String... regexes) {
		filterRegex(regex, regexes).through(HttpServletRequestWrapperFilter.class, filterConfig);
		filterRegex(regex, regexes).through(NoRedirectCasFilter.class, filterConfig);
	}
}
