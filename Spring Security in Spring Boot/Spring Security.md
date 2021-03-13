# Spring Security in Spring Boot

## Базовые определения

* `Аутентификация` - идентификация пользователя, `кто ты`?

* `Авторизация` - проверка прав пользователя, `какие действия ты можешь выполнять?`

* `Authentication` - объект, который хранит для каждого запроса информацию о пользователе (доверителе) и статусе его аутентификации.

* `SecurityContext` - информация о безопасности, которая ассоциирована с текущим потоком исполнения. Хранит объект `Authentication`.

* `SecurityContextHolder` - привязывает `SecurityContext` к текущему потоку исполнения. По умолчанию `ThreadLocal` - контекст безопосности доступен всем методам, исполняемым в рамках данного потока.

## DelegatingFilterProxy 

Поскольку фильтры являются компонентами спецификации `Servlet API` и не являются частью инфраструктуры Spring-а, они не имеют доступа к `ApplicationContext`. 

Для того, чтобы решить эту проблему и сделать некоторые фильтры Spring-managed (т.е. бинами), при запуске приложения создается экземпляр класса-фильтра `DelegatingFilterProxy`, содержащий параметр `targetBeanName`. Как только запрос попадает в `DelegatingFilterProxy`, он делегируется на обработку фильтру-бину, название которого указано в параметре `targetBeanName`.

```JAVA
package org.springframework.web.filter;

public class DelegatingFilterProxy extends GenericFilterBean {

	@Nullable
	private WebApplicationContext webApplicationContext; // Spring-контекст приложения

	@Nullable
	private String targetBeanName; // имя бина-фильтра, которому делегируется обработка запроса

	@Nullable
	private volatile Filter delegate; // бин-фильтр, которому делегируется обработка запроса

	public DelegatingFilterProxy(String targetBeanName, @Nullable WebApplicationContext wac) {
		// ...

		this.setTargetBeanName(targetBeanName);
		this.webApplicationContext = wac;
		
		// ...
	}

	// метод инициализации фильтра-бина для делегирования
	protected Filter initDelegate(WebApplicationContext wac) throws ServletException {
		String targetBeanName = getTargetBeanName();
		// ...
		Filter delegate = wac.getBean(targetBeanName, Filter.class);
		// ...
		return delegate;
	}

	// метод делегирования запроса бину с названием targetBeanName
	protected void invokeDelegate(
			Filter delegate, ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		delegate.doFilter(request, response, filterChain);
	}

	// ...
}

```

В свою очередь, `DelegatingFilterProxy` создается на основе компонента `DelegatingFilterProxyRegistrationBean` в классе автоконфигурации `SpringBoot`:

```JAVA
package org.springframework.boot.autoconfigure.security.servlet;

// ...
@Configuration
public class SecurityFilterAutoConfiguration {

	// ...

	@Bean
    @ConditionalOnBean(
        name = {"springSecurityFilterChain"}
    )
    public DelegatingFilterProxyRegistrationBean securityFilterChainRegistration(SecurityProperties securityProperties) {
        DelegatingFilterProxyRegistrationBean registration = new DelegatingFilterProxyRegistrationBean("springSecurityFilterChain", new ServletRegistrationBean[0]);
        registration.setOrder(securityProperties.getFilter().getOrder());
        registration.setDispatcherTypes(this.getDispatcherTypes(securityProperties));
        return registration;
    }

    // ...
```

Данный компонент содержит метод для получения объекта `DelegatingFilterProxy`:

```JAVA
package org.springframework.boot.web.servlet;

public class DelegatingFilterProxyRegistrationBean {
	@Override
	public DelegatingFilterProxy getFilter() {
		return new DelegatingFilterProxy(this.targetBeanName, getWebApplicationContext()) {
			// ...
		};
	}
}
```

Именно метод `getFilter()` вызывается механизмом конфигурации Sping для добавления `DelegatingFilterProxy` в `ServletContext`.

## FilterChainProxy

В части инфраструктуры Spring Security `DelegatingFilterProxy` первым принимает запрос и направляет его  цепочке фильтров безопасности (бину со значением, которое указано в `targetBeanName`). В качестве `targetBeanName` как правило указывается бин `springSecurityFilterChain`.

Ниже приведен код инициализации бина `springSecurityFilterChain` в классе конфигурации Spring:

```JAVA
package org.springframework.security.config.annotation.web.configuration;

@Configuration
public class WebSecurityConfiguration implements ImportAware, BeanClassLoaderAware {
	// ...
	
	@Bean
	public Filter springSecurityFilterChain() throws Exception {
		// ...
	}

	// ...
```

Что же представляет из себя бин `springSecurityFilterChain`? В качестве реализации данного бина используется класс `FilterChainProxy`, содержащий фильтры для обеспечения безопасности приложения:

![FilterChainProxy](https://github.com/MarselSidikov/about_spring/blob/master/images/security-filters.png)

Для каждого запроса создается "виртуальная цепочка фильтров" (Spring Security Filters), внутри которых происходит проверка безопасности запроса. При этом каждый из фильтров имеет возможность "заблокировать запрос", если он не соответствует критериям безопасности. Также, поскольку `FilterChainProxy` является бином, каждый из фильтров цепочки имеет доступ к контексту Spring.	

* Создание виртуальной цепочки фильтров:

```JAVA
package org.springframework.security.web;

public class FilterChainProxy extends GenericFilterBean {

	private void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		FirewalledRequest firewallRequest = this.firewall.getFirewalledRequest((HttpServletRequest) request);
		HttpServletResponse firewallResponse = this.firewall.getFirewalledResponse((HttpServletResponse) response);
		// ...
		VirtualFilterChain virtualFilterChain = new VirtualFilterChain(firewallRequest, chain, filters);
		virtualFilterChain.doFilter(firewallRequest, firewallResponse);
	}
}
```

В свою очередь, `VirtualFilterChain`, как вложенный класс `FilterChainProxy`, содержит список фильтров, которые необходимо применить к текущему URL:

```JAVA
private static final class VirtualFilterChain implements FilterChain {

		// ...

		private final List<Filter> additionalFilters; // список внутренних фильтров Spring Security

		private final int size; // количество внутренних фильтров

		private int currentPosition = 0; // номер текущего фильтра, выполняющего обработку запроса

		@Override
		public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
			if (this.currentPosition == this.size) {
			// ...
			this.currentPosition++;
			// получение текущего фильтра
			Filter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
			// ...
			// отправка запроса текущему фильтру, в качестве цепочки фильтров передается текущая виртуальная цепочка
			nextFilter.doFilter(request, response, this);
		}
	}
}
```

Рассмотрим подробнее некоторые из фильтров `VirtualFilterChain`, отвечающих за безопасность запросов.

### SecurityContextPersistenceFilter

Данный фильтр отвечает за работу с `SecurityContext` между запросами. Задачи - получить `SecurityContext` для текущего запроса, положить его в `SecurityContextHolder`, очистить `SecurityContextHolder` после выполнения запроса, сохранить изменения контекста после выполнения запроса.

```JAVA
package org.springframework.security.web.context;

public class SecurityContextPersistenceFilter extends GenericFilterBean {

	private SecurityContextRepository repo; // хранилище для SecurityContext


	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// ...
		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
		// получаем SecurityContext из хранилища до того, как будет выполнен запрос
		SecurityContext contextBeforeChainExecution = this.repo.loadContext(holder);
		try {
			// привязываем текущий контекст безопасности к потоку исполнения
			SecurityContextHolder.setContext(contextBeforeChainExecution);
			// ...
			// передаем запрос на обработку дальше
			chain.doFilter(holder.getRequest(), holder.getResponse());
		}
		finally {
			// после завершения запроса получаем контекст
			SecurityContext contextAfterChainExecution = SecurityContextHolder.getContext();
			// очищаем текущий поток исполнения от контекста безопасности
			SecurityContextHolder.clearContext();
			// сохраняем актуальный контекст безопасности в хранилище
			this.repo.saveContext(contextAfterChainExecution, holder.getRequest(), holder.getResponse());
			// ...
		}
	}
}
```

В качестве реализации `SecurityContextRepository` по умолчанию используется `HttpSessionSecurityContextRepository`.


### CsrfFilter

Данный фильтр отвечает за создание и проверку `csrf`-токенов.

```JAVA
package org.springframework.security.web.csrf;

public final class CsrfFilter extends OncePerRequestFilter {
	// ...

	private final CsrfTokenRepository tokenRepository; // компонент, отвечающий за хранение и создание токенов

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// загружаем существующий токен
		CsrfToken csrfToken = this.tokenRepository.loadToken(request);
		boolean missingToken = (csrfToken == null);
		// если токен отстутствует
		if (missingToken) {
			// создаем новый
			csrfToken = this.tokenRepository.generateToken(request);
			// сохраняем его для текущего запроса-ответа
			this.tokenRepository.saveToken(csrfToken, request, response);
		}
		// кладем информацию о csrf-токене как атрибут текущего запроса
		request.setAttribute(CsrfToken.class.getName(), csrfToken);
		request.setAttribute(csrfToken.getParameterName(), csrfToken);
		// нет смысла проверять не POST/PUT запросы
		if (!this.requireCsrfProtectionMatcher.matches(request)) {
			// ...
			filterChain.doFilter(request, response);
			return;
		}
		// для остальных запросов получаем токен из заголовка, либо из параметра запроса
		String actualToken = request.getHeader(csrfToken.getHeaderName());
		if (actualToken == null) {
			actualToken = request.getParameter(csrfToken.getParameterName());
		}
		// если токен неверный 
		if (!csrfToken.getToken().equals(actualToken)) {
			// создаем исключение и прерываем работу фильтров
			AccessDeniedException exception = (!missingToken) ? new InvalidCsrfTokenException(csrfToken, actualToken)
					: new MissingCsrfTokenException(actualToken);
			this.accessDeniedHandler.handle(request, response, exception);
			return;
		}
		filterChain.doFilter(request, response);
	}

}
```

По умолчанию, в качестве реализации `CsrfTokenRepository` используется `HttpSessionCsrfTokenRepository`, хранящий токен в сесии.

### LogoutFilter

Данный фильтр отвечает за "выход" пользователя из системы:

```JAVA
package org.springframework.security.web.authentication.logout;

public class LogoutFilter extends GenericFilterBean {
	// ...

	private RequestMatcher logoutRequestMatcher; // компонент, отвечающий за матчинг URL для выхода, например, URL должен соответствовать /lougout

	private final LogoutHandler handler; // компонент, содержащий логику, которую необходимо выполнить при выходе пользователя из системы

	private final LogoutSuccessHandler logoutSuccessHandler; // компонент, содержащий логику, которую необходимо выполнить при УСПЕШНОМ выходе пользователя из системы

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (requiresLogout(request, response)) { //если запрос соответствует необходимому URL (проверяется через logoutRequestMatcher)
			Authentication auth = SecurityContextHolder.getContext().getAuthentication(); // получение объекта текущей аутентификации
			// ...
			this.handler.logout(request, response, auth); // вызов необходимых обработчиков выхода, например - очистка cookies, csrf, remeber-me и.д.
			this.logoutSuccessHandler.onLogoutSuccess(request, response, auth); // вызов обработчика успешного выхода, например SimpleUrlLogoutSuccessHandler - переход на URL /signIn после выхода
			// завершение выполнения запроса
			return;
		}
		// передача запроса остальным фильтрам
		chain.doFilter(request, response);
	}
```

* Обработчики `LogoutFilter`

![Logout Handlers](https://github.com/MarselSidikov/about_spring/blob/master/images/logout_handlers.png)


## Аутентификация

Мы рассмотрели компоненты Spring Security, работающие в момент отправки запроса "залогиненным" пользователем. Теперь рассмотрим случай, когда пользователь вводит логин-пароль и для него требуется аутентификация.

В очереди `VirtualFilterChain` следующим после `LogoutFilter` идет `UsernamePasswordAuthenticationFilter`, задачей которго является аутентификация пользователя. Данный фильтр отрабатывает в случае стандартной настройки Spring Security в Spring Boot. Основная логика аутентификации описана в классе-предке `AbstractAuthenticationProcessingFilter`. Непосредственно внутри `
UsernamePasswordAuthenticationFilter` создается объект-имплементация `Authentication` - `UsernamePasswordAuthenticationToken`, включающего логин и пароль пользователя. После чего данный объект направляется компоненту `AuthenticationManager`, выполняющему проверку данных пользователя.


```JAVA
public class UsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	// ...

	// метод, задачей которого является создание объекта Authentication на основе входящего запроса
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		// ...
		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
		// ...
		return this.getAuthenticationManager().authenticate(authRequest);
	}
	// ...
```

## Общая схема работы Spring Security

![MAIN](https://github.com/MarselSidikov/about_spring/blob/master/images/main.png)