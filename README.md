# springsecurity

DB Configurations

create table users(username varchar (50) not null primary key,
password varchar (50) not null,
enabled boolean not null);

create table authorities (
	username varchar (50) not null,
    authority varchar (50) not null,
    constraint fk_authorities_users
    foreign key(username) references users(username));
    create unique index ix_auth_username on 
    authorities (username, authority);


insert into users (username, password, enabled) values 
("vaibhav", "password", true);

insert into authorities (username, authority) values ("vaibhav", "ROLE_USER");


Maven Dependency
Add following dependencies in pom.xml
1)	Dependency for mysql jdbc driver 
2)	Spring jdbc dependency


<dependency>
			<groupId>mysql</groupId>
			<artifactId>mysql-connector-java</artifactId>
			<version>5.1.6</version>
		</dependency>

		<dependency>
			<groupId>org.springframework</groupId>
			<artifactId>spring-jdbc</artifactId>
			<version>3.2.6.RELEASE</version>
		</dependency>
Changes in security-config.xml
Create a datasource for the database connection
Create jdbc connection

One way of achieving spring-security is having below configurations:
<authentication-manager>
        <authentication-provider user-service-ref="userDetailsService"/>
    </authentication-manager>
     
    <beans:bean id="dataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
        <beans:property name="driverClassName" value="com.mysql.jdbc.Driver" />
        <beans:property name="url" value="jdbc:mysql://localhost:3306/fitnessTracker" />
        <beans:property name="username" value="root"/>
        <beans:property name="password" value="password"/>
    </beans:bean>
    
    <beans:bean id="userDetailsService" class="org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl">
        <beans:property name="dataSource" ref="dataSource" /> 
    </beans:bean>

Other way of achieving this is
<authentication-manager>
        <authentication-provider>
            <jdbc-user-service data-source-ref="dataSource" />
        </authentication-provider>
    </authentication-manager>
     
    <beans:bean id="dataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
        <beans:property name="driverClassName" value="com.mysql.jdbc.Driver" />
        <beans:property name="url" value="jdbc:mysql://localhost:3306/fitnessTracker" />
        <beans:property name="username" value="root"/>
        <beans:property name="password" value="password"/>
    </beans:bean>

Spring Security Client Integration

Spring Security Tag Library

1)	Declared in your JSP page
<%@ taglib prefix=”sec” uri=”http
Uri dosent download it, it looks up the key which is contained in the jar
2)	Three tags:
authorize – used to check whether the components in the elements should be evaluated or not
authentication – used to get access to the object that is used to represent the current logged in user.
Accesscontrollist - 

Maven Dependency for Spring Security Tag Library

<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-taglibs</artifactId>
			<version>3.2.0.RELEASE</version>
		</dependency>

Authentication Tag
Used to gain access to the authenticated users
Tag has a property attribute for accessing properties of the suthentications object
1)	Name
2)	authorities
3)	credentials – password is not available
4)	details
5)	principal – 
6)	isAuthenticated

Displaying the Current User

Add declaration to the JSP header
<%@taglib prefix="sec" uri="http://www.springframework.org/secutiy/tags" %>
Use following where you want to show username of the logged in user
<sec:authentication property="name"/>

Authorization tag
It is used to restrict access to certain pieces of the page
Following attributes are there in authorization tag:
1)	url – if the url pattern defined in the security-config file matches with the ROLE of the user
2)	var – is a page scoped variables, store once and use it in thorough page
3)	method: 
4)	access: used with el
5)	ifAnyGranted
6)	ifAllGranted
7)	ifNotGranted

Wrap following tag around an element that needed specific role to access
<sec:authorize ifAnyGranted="ROLE_ADMIN">
        <a class="btn btn-primary" href="editGoal.html">
          Edit Goal »
        </a>
 </sec:authorize>

Password Storage

MD5
1)	One way algorithm
2)	Just add a 
<password-encoder hash=”md5”/>
3)	Need a small application to create users which will create MD5 encrypted password

Following test case shows the password encoder provided by java
public class PasswordHash extends TestCase {
	
	public void testMD5Hash() {
		String password ="password";
		Md5PasswordEncoder passwordEncoder = new Md5PasswordEncoder();
		String hashedPassword = passwordEncoder.encodePassword(password, null);
		System.out.println(hashedPassword);
	}
}
Put following in the security-config file
<authentication-manager>
        <authentication-provider>
            <password-encoder hash="md5" />
            <jdbc-user-service data-source-ref="dataSource" />
        </authentication-provider>
    </authentication-manager>
     
MD5 is still weak
Salt helps add security, but adds complexity
BCrypt
BCrypt adds a salt with no extra configuration
<authentication-manager>
        <authentication-provider>
            <password-encoder hash="bcrypt" />
            <jdbc-user-service data-source-ref="dataSource" />
        </authentication-provider>
    </authentication-manager>

public void testBCryptHash() {
		String password = "password";
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String pwd= encoder.encode(password);
		System.out.println(pwd);
	}


Customizing Spring Security

Basic Authentication

A small popup that will ask for username and password:
Its very simple: just put <http-basic/>
<http auto-config="true">
        <intercept-url pattern="/**" access="ROLE_USER"/>
        <http-basic/>
    </http>

Change Login Form
Following steps needed:
1.	Form-login element
2.	Intercept-url element

<http auto-config="true">
        <intercept-url pattern="/login.html" access="IS_AUTHENTICATED_ANONYMOUSLY"/>
        <intercept-url pattern="/**" access="ROLE_USER"/>
        <!-- <http-basic/> -->
        <form-login login-page="/login.html"/>
    </http>
Here login-page is login.html which will route through spring
3.	LoginController
4.	Login.jsp

Login.jsp
J_spring_security_check
j_username
j_password

<c:if test="${not empty error}">
		<div class="errorblock">
			Your login was unsuccessful. <br/>
			Caused: ${sessionScope["SPRING_SECURITY_LAST_EXCEPTION"].message}
		</div>
	</c:if>
	<form action="j_spring_security_check" name="f" method="post">
		<table>
			<tr>
				<td>User:</td>
				<td><input type="text" name="j_username" value=""></td>
			</tr>
			<tr>
				<td>Password:</td>
				<td><input type="password" name="j_password"></td>
			</tr>
			<tr>
				<td colspan="2"><input type="submit" name="Submit" value="Submit"> </td>
			</tr>
			<tr>
				<td colspan="2"><input type="reset" name="reset" value="reset"> </td>
			</tr>
		</table>
	</form>

LoginController

@Controller
public class LoginController {
	
	@RequestMapping(value="/login", method=RequestMethod.GET)
	public String login(ModelMap model){
		System.out.println("In the login Method");
		return "login";
	}
}

We are already having following configuration in our servlet-config.xml so all things will work well
<bean class="org.springframework.web.servlet.view.InternalResourceViewResolver" 
	 p:prefix="/WEB-INF/jsp/" p:suffix=".jsp" p:order="2"/>
Run the project but, error message will not be shown on UI for this you have to do Failed Login Configurations
Failed Login Configuration
1)	Add Error Param to response
2)	Form-element authentication-failure-url
3)	Intercept-url for the loginFailed
4)	loginFailed entry in LoginController

<http auto-config="true">
        <intercept-url pattern="/login.html" access="IS_AUTHENTICATED_ANONYMOUSLY"/>
        <intercept-url pattern="/**" access="ROLE_USER"/>
        <intercept-url pattern="/loginFailed.html" access="IS_AUTHENTICATED_ANONYMOUSLY"/>
        <!-- <http-basic/> -->
        <form-login login-page="/login.html" authentication-failure-url="/loginFailed.html"/>
        
    </http>

LoginController changes:
@RequestMapping(value="/loginFailed", method=RequestMethod.GET)
	public String loginFailed(ModelMap model){
		System.out.println("Login Failed");
		model.addAttribute("error", "true");
		return "login";
	}
Now our login page will show error message as we are setting it in model.addAttribute

Logout Configuration

1)	add a logout element
2)	intercept-url
3)	LoginController
4)	Logout.jsp

Security-config.xml changed
<http auto-config="true">
        <intercept-url pattern="/login.html" access="IS_AUTHENTICATED_ANONYMOUSLY"/>
        <intercept-url pattern="/**" access="ROLE_USER"/>
        <intercept-url pattern="/loginFailed.html" access="IS_AUTHENTICATED_ANONYMOUSLY"/>
        <intercept-url pattern="/login.html" access="IS_AUTHENTICATED_ANONYMOUSLY"/>
        <!-- <http-basic/> -->
        <form-login login-page="/login.html" authentication-failure-url="/loginFailed.html"/>
        <logout logout-success-url="/logout.html"/>
    </http>

LoginController
@RequestMapping(value="logout",  method=RequestMethod.GET)
	public String logout(ModelMap model){
		return "logout";
	}
Logout.jsp
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Fitness Tracker Custom Logout Page</title>
</head>
<body>
<h3>Fitness Tracker Custom Logout Page</h3>
<h1>You have been logout thanks for using our app</h1>
</body>
</html>

Index.jsp page – Put the link for logout
<a class="btn btn-warning" href="j_spring_security_logout"> Logout</a>

403 Configuration

1) access-denied-handler
2) 403.jsp
3) Error403 in LoginController
<http auto-config="true">
        <intercept-url pattern="/login.html" access="IS_AUTHENTICATED_ANONYMOUSLY"/>
        <intercept-url pattern="/**" access="ROLE_USER"/>
        <intercept-url pattern="/loginFailed.html" access="IS_AUTHENTICATED_ANONYMOUSLY"/>
        <intercept-url pattern="/logout.html" access="IS_AUTHENTICATED_ANONYMOUSLY"/>
        <intercept-url pattern="/403.html" access="IS_AUTHENTICATED_ANONYMOUSLY"/>
        <!-- <http-basic/> -->
        <form-login login-page="/login.html" authentication-failure-url="/loginFailed.html"/>
        <logout logout-success-url="/logout.html"/>
        <access-denied-handler error-page="/403.html"/>
    </http>

Changes in Login Controller
	@RequestMapping(value="403")
	public String error403(ModelMap model){
		return "403";
	}

Enabling Security with Expressions
Expressions simplify the complex Boolean logic into readable form
Use-expressions=”true”
hasRole
hasAnyRole
permitAll
hasPermission -  is used to compare property of the domain object
<http auto-config="true" use-expressions="true">
        <intercept-url pattern="/login.html" access="permitAll"/>
        <intercept-url pattern="/**" access="hasRole('ROLE_USER')"/>
        <intercept-url pattern="/loginFailed.html" access="permitAll"/>
        <intercept-url pattern="/logout.html" access="permitAll"/>
        <intercept-url pattern="/403.html" access="permitAll"/>
        <!-- <http-basic/> -->
        <form-login login-page="/login.html" authentication-failure-url="/loginFailed.html"/>
        <logout logout-success-url="/logout.html"/>
        <access-denied-handler error-page="/403.html"/>
    </http>

Method Level Security
Uses the expression
@PreAuthorize
@PostAuthorize
<global-method-security /> this allows three types of annotations:
Pre-post-annotations
Secured-annotations
Jsr250-annotations

Context Matter – We need to put the <global-method-security /> tag into the context as describe below
Spring Coontext
1)	Mvc context – loaded by servlet
2)	Security  context – loaded by loader listener
In this approach MVC context can see things in security context however vice versa is not possible
Therefore we have to put <global-method-security /> tag in MVC context.
Add below line in servlet-config.xml
	<security:global-method-security pre-post-annotations="enabled"/>
Make following changes in the controller method:

@PreAuthorize("hasRole('ROLE_ADMIN')")
	@RequestMapping(value = "addGoal", method = RequestMethod.POST)
	public String updateGoal(@Valid @ModelAttribute("goal") Goal goal, BindingResult result) {
		
		System.out.println("result has errors: " + result.hasErrors());
		
		System.out.println("Goal set: " + goal.getMinutes());
		
		if(result.hasErrors()) {
			return "addGoal";
		}
		
		return "redirect:index.jsp";
	}

Permissions
1)	Able to enable per object permissions
a.	A level deeper than ROLE
2)	hasPermission(#goal, ‘createGoal’)
a.	Tied to an object, #goal
b.	Permission, createGoal
3)	<security:expression-handler ref=”fitnessExpressionHandler” />
4)	Custom Permission Evaluator
FitnessPermissionEvaluator


Permission Evaluator
1)	Interface with two methods
hasPermission(Authentication auth, Object targetObj, Object permission)
hasPermission(Authentication auth, Serializable id, String type, Object permission)
@PreAuthorize("hasRole('ROLE_ADMIN') and hasPermission(#goal, 'createGoal’)")
	
create table permissions (
username varchar(50) not null,
target varchar(50) not null,
permission varchar(50) not null,
constraint fk_permissions_users foreign key(username) references users(username));
create unique index ix_perm_username on permissions (username, target, permission);
insert into permissions (username, target, permission) values ("vaibhav", "com.pluralsight.model.Goal", "createGoal");

FitnessPermissionEvaluator
package com.pluralsight.security;

import java.io.Serializable;

import javax.sql.DataSource;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

public class FitnessPermissionEvaluator implements PermissionEvaluator {
	
	private DataSource datasource;

	public DataSource getDatasource() {
		return datasource;
	}

	public void setDatasource(DataSource datasource) {
		this.datasource = datasource;
	}

	public boolean hasPermission(Authentication auth, Object targetDomainObject, Object permission) {
		JdbcTemplate template = new JdbcTemplate(datasource);
		Object [] args = {((User)auth.getPrincipal()).getUsername(), 
				targetDomainObject.getClass().getName(), 
				permission.toString()};
		int count = template.queryForObject("select count(*) from permissions p where "
				+ "p.username =? and p.target =? and p.permission = ? ", args, Integer.class);
		
		if(count == 1){
			return true;
		}else{
			return false;
		}
	}

	public boolean hasPermission(Authentication arg0, Serializable arg1,
			String arg2, Object arg3) {
		// TODO Auto-generated method stub
		return false;
	}

}

Changes to be done in servlet-config.xml file
<security:global-method-security pre-post-annotations="enabled">
	    	<security:expression-handler ref="fitnessExpressionHandler"/>
	    </security:global-method-security>
	
	<bean id="fitnessExpressionHandler" 
	    class="org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler">
	    <property name="permissionEvaluator">
	        <bean id="permissionEvaluator" class="com.pluralsight.security.FitnessPermissionEvaluator">
	            <property name="datasource" ref="dataSource"/>
	        </bean>
	    </property>
	</bean>

Authentication Using LDAP

Ldap-authentication-provider
Features are
Group-search-filter
Group-search-base
User-search-base
User-search-filter
Can be combined to user-details-service element

ldap-server
helps connecting to ldap server
loads an ldif file – flat file for storing our users
default port 389 can be overridden

Maven dependencies
	<dependency>
		<groupId>org.slf4j</groupId>
		<artifactId>slf4j-simple</artifactId>
		<version>1.5.6</version>
	</dependency>
	<dependency>
		<groupId>org.apache.directory.server</groupId>
		<artifactId>apacheds-all</artifactId>
		<version>1.5.5</version>
	</dependency>
	<dependency>
		<groupId>org.springframework.security</groupId>
		<artifactId>spring-security-ldap</artifactId>
		<version>3.2.0.RELEASE</version>
	</dependency>

Changes to be done in security-config file

<ldap-server ldif="classpath:users.ldif" />
     <authentication-manager>
         <ldap-authentication-provider
             group-search-filter="member-{0}"
             group-search-base="ou=groups"
             user-search-base="ou=people"
             user-search-filter="uid={0}"/>
     </authentication-manager>

Create following user.ldif file
dn: ou=groups,dc=springframework,dc=org
objectclass: top
objectclass: organizationalUnit
ou: groups

dn: ou=people,dc=springframework,dc=org
objectclass: top
objectclass: organizationalUnit
ou: people

dn: uid=rod,ou=people,dc=springframework,dc=org
objectclass: top
objectclass: person
objectclass: organizationalUnit
objectclass: inetOrgPerson
cn: Vaibhav Sharma
sn: Sharma
uid: vaibhav
userPassword: sharma

Forcing the use of HTTPS

Main in the middle attack
Someone is watching traffic over the network and is able to grab user information using a key logger
Spring can for requests over HTTPS
Require-channel=”hhtps”
Certificate
Requires a certificate
For development a self-signed cert is fines but not for production- we can use a keytool command that use java to generate a self signed certificate
Connector – uncomment it in tomcat for SSL
Requires-channel
Generating the certificate
D:\Software\tomcat\apache-tomcat-7.0.64-windows-x64\apache-tomcat-7.0.64\bin>keytool -genkey -alias tomcat -keyalg RSA -keystore D:\Software\tomcat\apache-tomcat-7.0.64-windows-x64\apache-tomcat-7.0.64\bin\tomcat
Keytool is in jre/bin/ and configure it in PATH variable
Keep password as “changeit”

   <Connector port="8443" protocol="org.apache.coyote.http11.Http11Protocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               clientAuth="false" sslProtocol="TLS"
               keystoreFile="D:\Software\tomcat\apache-tomcat-7.0.64-windows-x64\apache-tomcat-7.0.64\bin\tomcat" 
               keystorePassword="changeit"/>

now we can access application on https://localhost:8443 port also
If we want to say that our application will have to run only on https, we need to do the following configurations as well




