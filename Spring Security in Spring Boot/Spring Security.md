# Spring Security in Spring Boot

## Базовые определения

* `Аутентификация` - идентификация пользователя, `кто ты`?

* `Авторизация` - проверка прав пользователя, `какие действия ты можешь выполнять?`

* `Authentication` - объект, который хранит для каждого запроса информацию о пользователе (доверителе) и статусе его аутентификации.

* `SecurityContext` - информация о безопасности, которая ассоциирована с текущим потоком исполнения. Хранит объект `Authentication`.

* `SecurityContextHolder` - привязывает `SecurityContext` к текущему потоку исполнения. По умолчанию `ThreadLocal` - контекст безопосности доступен всем методам, исполняемым в рамках данного потока.

## Компоненты SpringSecurity

### DelegatingFilterProxy 

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

### FilterChainProxy

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

В очереди `VirtualFilterChain` следующим после `LogoutFilter` идет `UsernamePasswordAuthenticationFilter`, задачей которго является аутентификация пользователя. Данный фильтр отрабатывает в случае стандартной настройки Spring Security в Spring Boot. Непосредственно внутри `
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

Основная логика аутентификации описана в классе-предке `AbstractAuthenticationProcessingFilter`. Именно здесь происходит проверка на необходимость проверки логина и пароля:

```JAVA
package org.springframework.security.web.authentication;

public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean
		implements ApplicationEventPublisherAware, MessageSourceAware {

	// менеджер аутентификации

	private AuthenticationManager authenticationManager;

	// ...

	// данный объект определяет, является ли данный запрос запросом на аутентификацю
	// в классе UsernamePasswordAuthenticationFilter по-умолчанию это POST /login
	private RequestMatcher requiresAuthenticationRequestMatcher;

	// метод фильтрации
	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// если метод не является запросом на авторизацию, отправляем запрос дальше
		if (!requiresAuthentication(request, response)) {
			chain.doFilter(request, response);
			return;
		}

		try {
			// аутентификация пользователя (реализация данного метода описана в UsernamePasswordAuthenticationFilter)
			Authentication authenticationResult = attemptAuthentication(request, response);
			
			// ...

			// успешная аутентификация
			successfulAuthentication(request, response, chain, authenticationResult);
		}
		// ...
		catch (AuthenticationException ex) {
			// Если произошла ошибка аутентификации
			unsuccessfulAuthentication(request, response, ex);
		}
	}


	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		// привязываем аутентификацию к текущему потоку
		SecurityContextHolder.getContext().setAuthentication(authResult);
		
		this.rememberMeServices.loginSuccess(request, response, authResult);
		// ...
	}
}
```

### AuthenticationManager

Как было сказано выше, логику аутентификации содержат классы-имплементации `AuthenticationManager`. Сам интерфейс имеет следующую структуру:

```JAVA
package org.springframework.security.authentication;

public interface AuthenticationManager { 

	Authentication authenticate(Authentication authentication) throws AuthenticationException;

}
```

Метод `authenticate()` возвращает объект `Authentication` со значением `authenticated=true` в случае успешной аутентификации, либо выбрасывает `AuthenticationException` в противоположном случае. При неопределенности возвращается `null`.

По умолчанию в качестве реализации `AuthenticationManager` используется `ProviderManager`. Внутри объекта данного класса содержится цепочка экземпляров `AuthenticationProvider`-ов. Задача `ProviderManager` прогнать объект аутентификации по цепочке провайдеров. Объекты аутентифкации могут иметь разные типы (например, один из них - `UsernamePasswordAuthenticationToken`). Для каждого из этих типов существует своя реализация `AuthenticationProvider`. В методе `supports()` объекта `AuthenticationProvider` содержится логика проверки, подходит ли данный провайдер для работы с данным типом аутентификации. Сам интерфейс `AuthenticationProvider` имеет следующую структуру:

```JAVA
package org.springframework.security.authentication; 

public interface AuthenticationProvider {
	// метод для проверки соответствия типа объекта аутентификации текущему провайдеру
	boolean supports(Class<?> authentication);


	// метод аутентификации для объекта аутентификации конкретного типа
	Authentication authenticate(Authentication authentication) throws AuthenticationException;
```

Понимая назначение `AuthenticationProvider`, рассмотрим структуру `ProviderManager`:

```JAVA
package org.springframework.security.authentication;

public class ProviderManager implements AuthenticationManager, MessageSourceAware, InitializingBean {

	// список AuthenticationProvider-ов
	private List<AuthenticationProvider> providers = Collections.emptyList();

	// родительский AuthenticatoinManager
	private AuthenticationManager parent;


	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// класс объекта аутентификации
		Class<? extends Authentication> toTest = authentication.getClass();

		AuthenticationException lastException = null;

		// ...

		// итерируем список провайдеров
		for (AuthenticationProvider provider : getProviders()) {
			// если текущий провайдер не подошел для типа объекта входящей аутентификации - идем дальше
			if (!provider.supports(toTest)) {
				continue;
			}

			try {
				// получаем результат выполнения текущей аутентификации выбранным провайдером
				result = provider.authenticate(authentication);
				// ... 
			}
			// ...
			catch (AuthenticationException ex) {
				// если аутентификация прошла неуспешно - сохранили выбрашенное провайдером исключение
				lastException = ex;
			}
		}
		// если провайдер не смог сделать однозначный вывод по аутентификации - передаем аутентификацию parent-менеджеру аутентификаций
		if (result == null && this.parent != null) {
			// попытка выполнить аутентификацю parent-менеджером
			try {
				// запоминаем результат аутентификации
				parentResult = this.parent.authenticate(authentication);
				result = parentResult;
			}
			// ...
			catch (AuthenticationException ex) {
				// если было выброшено исключение - запоминаем его
				parentException = ex;
				lastException = ex;
			}
		}

		// если по итогу имеем положительный результат аутентифкации
		if (result != null) {
			// ...

			// возвращаем результат
			return result;
		}

		// ...

		// в случае если никто из провайдеров, а также parent-менеджер не смогли провести аутентификацию - выбрасываем последнее сохраненное исключение
		throw lastException;
	}
```

Рассмотрим механизм аутентификации в конкретном приложении SpringSecurity, а также разберемся с назначением parent-менеджера аутентифкации.

В случае, когда запрос попадает в `ProviderManager` нашего приложения, мы наблюдаем следующую ситуацию:

![PROVIDER](https://github.com/MarselSidikov/about_spring/blob/master/images/Provider.png)

Мы видим, что наш `AuthenticationProvider` в списке провайдеров содержит экземпляры `AnonymousAuthenticationProvider` и `RememberMeAuthenticationProvider`. В качестве parent-менеджера по умолчанию задан аналогичный экземпляр `ProverManager`, содержащий `DaoAuthenticationProvider` внутри списка провайдеров. 

Таким образом, объект `Authentication` проходит следующий путь:

1. `AnonymousAuthenticationProvider`
2. `RememberMeAuthenticationProvider`
3. `DaoAuthenticationProvider`

По факту, классы `AnonymousAuthenticationProvider` и `RememberMeAuthenticationProvider` не представляют для нас большого интереса, поэтому отложим их рассмотрение.

Но, какую роль играет parent-менеджер? На самом деле, в приложениях защищенные ресурсы подвергаются логической группировке (например, все ресурсы, которые соответствуют паттерну `/api/**`, либо `/static/**` и т.д.). Для каждой из таких групп назначается свой выделенный `AuthenticationManager`. При этом, для каждого из выделенных менеджеров сущесвтует parent-менеджер, который является глобальным и используется, когда ни один из менеджеров не может принять решение об аутентификации. 

![PROVIDERS HIERARCHY](https://github.com/MarselSidikov/about_spring/blob/master/images/hierarchy.png)

В нашем случае, выделенным `AuthenticationManager`-ом является `ProviderManager`, содержащий `AnonymousAuthenticationProvider` и `RememberMeAuthenticationProvider` и в целом для нас бесполезный. Настоящая работа по аутентификации происходит в parent-менеджере, содержащем `DaoAuthenticationProvider`. Именно этот менеджер настраивается в конфигурации SpringBoot-приложения с помощью `AuthenticationManagerBuilder`:

```JAVA
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	// ...
	@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }
}
```

Сам `DaoAuthenticationProvider` содержит логику аутентификации, привязанной к `PasswordEncoder` и `UserDerailsService`. Основная логика аутентификации с помошью `UserDetails` описана в классе-предке `AbstractUserDetailsAuthenticationProvider` (из приведенного кода исключена логика кэширования):

```JAVA
package org.springframework.security.authentication.dao;

public abstract class AbstractUserDetailsAuthenticationProvider
		implements AuthenticationProvider, InitializingBean, MessageSourceAware {

	// данный провайдер рассматривает только UsernamePasswordAuthenticationToken 
	@Override
	public boolean supports(Class<?> authentication) {
		return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// получаем имя пользователя
		String username = determineUsername(authentication);

		// ...

			try {
				// получаем пользователя по его имени 
				UserDetails user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
			}
			// в случае, если пользователь не был найден
			catch (UsernameNotFoundException ex) {
				// выбрасываем исключение
				throw new BadCredentialsException(this.messages
						.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
			}
			// ...
		}
		// ...
		// дополнительные проверки, необходимые для аутентификации
		additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
		// ...
		Object principalToReturn = user;
		// ...

		// возвращаем результат аутентификации с дополнительными механизмами гарантии наличия исходных учетных данных
		return createSuccessAuthentication(principalToReturn, authentication, user);
	}

	protected Authentication createSuccessAuthentication(Object principal, Authentication authentication,
			UserDetails user) {
		// создание данного объекта подразумевает вызов конструктора с authenticated=true у UsernamePasswordAuthenticationToken
		UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(principal,
				authentication.getCredentials(), this.authoritiesMapper.mapAuthorities(user.getAuthorities()));
		result.setDetails(authentication.getDetails());
		return result;
	}

	// реализован в DaoAuthenticationProvider
	protected abstract UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException;

	// реализован в DaoAuthenticationProvider
	protected abstract void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication) throws AuthenticationException;

	// ...
```

В классе `DaoAuthenticationProvider` нас интересуют методы `retrieveUser()` и `additionalAuthenticationChecks()`

```JAVA
package org.springframework.security.authentication.dao;

public class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

	// ...

	private PasswordEncoder passwordEncoder;

	private UserDetailsService userDetailsService;

	@Override
	protected final UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		
		// ...
		try {
			// получение пользователя из сервиса
			UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
			// если пользователь не получен, выбрасываем исключение
			if (loadedUser == null) {
				throw new InternalAuthenticationServiceException(
						"UserDetailsService returned null, which is an interface contract violation");
			}
			// возвращаем загруженного пользователя
			return loadedUser;
		}
		// в случае возникновения исключения - оборачиваем/пробрасываем их 
		catch (UsernameNotFoundException ex) {
			// ...
			throw ex;
		}
		catch (InternalAuthenticationServiceException ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
		}
	}

	
	@Override
	@SuppressWarnings("deprecation")
	protected void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
		// если отсутствуют данные для аутентификации
		if (authentication.getCredentials() == null) {
			// выбрасываем исключение
			throw new BadCredentialsException(this.messages
					.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
		}
		// получаем текущий пароль пользователя
		// выполняем проверку пароля с помощью passwordEncoder
		String presentedPassword = authentication.getCredentials().toString();
		if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
			throw new BadCredentialsException(this.messages
					.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
		}
	}

```

Таким образом, результатом работы цепочки `UsernamePasswordAuthenticationFilter` -> `AuthenticationManager` -> `DaoAuthenticationProvider` является объект `Authentication`, содержащий значение `authenticated=true`, далее этот объект помещяется в `SecurityContext` с помощью `SecurityContextHolder` в `AbstractAuthenticationProcessingFilter`.

## Авторизация или предоставление доступа

После того, как для запроса был создан объект `Authentication` с указанным параметром аутентификации, необходимо проверить, имеет ли пользователь доступ к запрашиваемому URL. 

Пусть имеем следующую настройку в конфигурации Spring Security:

```JAVA
.antMatchers("/users").hasAuthority("ADMIN")
```

В таком случае для аутентифицированного пользователя запрос после прохождения цепочки фильтров попадает в последний - `FilterSecurityInterceptor`, задачей которого является авторизация пользоавтеля по URL:



Рассмотрим интерфейс `AccessDecisionManager`, объектам-имплементациям которого делегируется работа по авторизации пользователя:

```
package org.springframework.security.web.access.intercept;


```

```JAVA
public class FilterSecurityInterceptor extends AbstractSecurityInterceptor implements Filter {

	// ...

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		invoke(new FilterInvocation(request, response, chain));
	}

	public void invoke(FilterInvocation filterInvocation) throws IOException, ServletException {
		// ...

		// авторизация запроса
		InterceptorStatusToken token = super.beforeInvocation(filterInvocation);

		try {
			// направление запроса далее по цепочке
			filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
		}
		// ...
	}
```

Класс `FilterSecurityInterceptor` является потомком класса `AbstractSecurityInterceptor`, именно в нем вызывается основная логика по работе с авторизацией: 

```JAVA
package org.springframework.security.access.intercept;

public abstract class AbstractSecurityInterceptor
		implements InitializingBean, ApplicationEventPublisherAware, MessageSourceAware {

		// менеджер авторизации
		private AccessDecisionManager accessDecisionManager;

		// object содержит информацию о самом запросе, в данном случае - GET /users
		protected InterceptorStatusToken beforeInvocation(Object object) {
			// ...

			// получение определенных атрибутов (правил), позволяющих определить владельца ресурса (т.е. выполнить авторизацию)
			// в данном случае - строка hasAuthority('ADMIN')
			Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource().getAttributes(object);
			// получение текущего объекта аутентификации из SecuryContextHolder-а
			Authentication authenticated = authenticateIfRequired();
			// выполнение авторизации
			attemptAuthorization(object, attributes, authenticated);
			// ...
		}

		
		private void attemptAuthorization(Object object, Collection<ConfigAttribute> attributes,
			Authentication authenticated) {
			try {
				// выполнение авторизации с помощью AcessDecisionManager
				this.accessDecisionManager.decide(authenticated, object, attributes);
			}
			catch (AccessDeniedException ex) {
				throw ex;
		}
	}
}
```

В свою очередь, интерфейс `AccessDecisionManager` содержит шлавный метод авторизации:

```JAVA
package org.springframework.security.access;

public interface AccessDecisionManager {
	// метод принимает решение по предоставлению доступа
	void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
			throws AccessDeniedException, InsufficientAuthenticationException;
}
```
 `AccessDecisionManager` имплементируется несколькими классами, наибольший интерес представляет класс `AffirmativeBased`. Данный класс является потомком класса `AbstractAccessDecisionManager`:

```JAVA
package org.springframework.security.access.vote;

public abstract class AbstractAccessDecisionManager
		implements AccessDecisionManager, InitializingBean, MessageSourceAware {

	private List<AccessDecisionVoter<?>> decisionVoters;

	// ...
}
```

Каждый из `AccessDecisionVoter` имеет метод, `int vote(Authentication authentication, S object, Collection<ConfigAttribute> attributes);`. Данный метод определяет, имеет ли пользователь с аутентификацией `authentication` доступ к объекту `object`, учитывая определенный набор правил доступа `attibutes`.

Сам `AffirmativeBased` имеет следующую структуру:

```JAVA
package org.springframework.security.access.vote;

public class AffirmativeBased extends AbstractAccessDecisionManager {

	// ... 
	@Override
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
			throws AccessDeniedException {
		int deny = 0;
		// итерируем список voter-ов
		for (AccessDecisionVoter voter : getDecisionVoters()) {
			// получаем результат, имеет ли пользователь authentication доступ к object с учетом правил configAttributes
			int result = voter.vote(authentication, object, configAttributes);
			// если хотя бы один из voter-ов дал доступ, авторизация считается пройденной
			switch (result) {
			case AccessDecisionVoter.ACCESS_GRANTED:
				return;
			case AccessDecisionVoter.ACCESS_DENIED:
				deny++;
				break;
			default:
				break;
			}
		}
		// если доступ никто не разрешил, при этом имеются запреты на этот запрос, то выбрасываем сключение
		if (deny > 0) {
			throw new AccessDeniedException(
					this.messages.getMessage("AbstractAccessDecisionManager.accessDenied", "Access is denied"));
		}

		// ...
	}

```

В нашем случае наблюдаем следующую картину:

![VOTERS](https://github.com/MarselSidikov/about_spring/blob/master/images/voters.png)

Следовательно, внутри `AttempBased` с помощью единственного voter-а `WebExpressionVoter` происходит решение, стоит ли предоставить доступ к объекту `FilterInvocation [GET /users]` с учетом атрибута-правила `hasAuthority('ADMIN')`.

## Общая схема работы Spring Security

![MAIN](https://github.com/MarselSidikov/about_spring/blob/master/images/main.png)