# JSON Web Token (JWT)

## What is JSON Web Token?

JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA or ECDSA.

Although JWTs can be encrypted to also provide secrecy between parties, we will focus on signed tokens. Signed tokens can verify the integrity of the claims contained within it, while encrypted tokens hide those claims from other parties. When tokens are signed using public/private key pairs, the signature also certifies that only the party holding the private key is the one that signed it.

## When should you use JSON Web Tokens?

Here are some scenarios where JSON Web Tokens are useful:

- **Authorization**: This is the most common scenario for using JWT. Once the user is logged in, each subsequent request will include the JWT, allowing the user to access routes, services, and resources that are permitted with that token. Single Sign On is a feature that widely uses JWT nowadays, because of its small overhead and its ability to be easily used across different domains.
  
- **Information Exchange**: JSON Web Tokens are a good way of securely transmitting information between parties. Because JWTs can be signed—for example, using public/private key pairs—you can be sure the senders are who they say they are. Additionally, as the signature is calculated using the header and the payload, you can also verify that the content hasn't been tampered with.

## What is the JSON Web Token structure?

In its compact form, JSON Web Tokens consist of three parts separated by dots (.), which are:

- Header
- Payload
- Signature

Therefore, a JWT typically looks like the following:

```
xxxxx.yyyyy.zzzzz
```

### Header:

The header typically consists of two parts: the type of the token, which is JWT, and the signing algorithm being used, such as HMAC SHA256 or RSA.

Example:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Then, this JSON is Base64Url encoded to form the first part of the JWT.

### Payload:

The second part of the token is the payload, which contains the claims. Claims are statements about an entity (typically, the user) and additional data. There are three types of claims: registered, public, and private claims.

- **Registered claims**: These are a set of predefined claims which are not mandatory but recommended, to provide a set of useful, interoperable claims. Some of them are: `iss` (issuer), `exp` (expiration time), `sub` (subject), `aud` (audience), and others. Notice that the claim names are only three characters long as JWT is meant to be compact.
- **Public claims**: These can be defined at will by those using JWTs. But to avoid collisions they should be defined in the IANA JSON Web Token Registry or be defined as a URI that contains a collision resistant namespace.
- **Private claims**: These are the custom claims created to share information between parties that agree on using them and are neither registered or public claims.

An example payload could be:

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

The payload is then Base64Url encoded to form the second part of the JSON Web Token.

**Note**: For signed tokens this information, though protected against tampering, is readable by anyone. Do not put secret information in the payload or header elements of a JWT unless it is encrypted.

### Signature:

To create the signature part you have to take the encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign that. For example, if you want to use the HMAC SHA256 algorithm, the signature will be created in the following way:

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

The signature is used to verify the message wasn't changed along the way, and, in the case of tokens signed with a private key, it can also verify that the sender of the JWT is who it says it is.


### Putting it all together:


The output is three Base64-URL strings separated by dots that can be easily passed in HTML and HTTP environments, while being more compact when compared to XML-based standards such as SAML.
The following shows a JWT that has the previous header and payload encoded, and it is signed with a secret. 

![image](https://github.com/user-attachments/assets/a63c1ad5-09af-42ec-bae4-0633ede5cb70)

 

If you want to play with JWT and put these concepts into practice, you can use `jwt.io` Debugger to decode, verify, and generate JWTs.
![image](https://github.com/user-attachments/assets/fdb1216e-62ce-417f-9f25-b1b06d2fd446)

## How do JSON Web Tokens work?

In authentication, when the user successfully logs in using their credentials, a JSON Web Token will be returned. Since tokens are credentials, great care must be taken to prevent security issues. In general, you should not keep tokens longer than required.

You also should not store sensitive session data in browser storage due to lack of security.

Whenever the user wants to access a protected route or resource, the user agent should send the JWT, typically in the Authorization header using the Bearer schema. The content of the header should look like the following:

```
Authorization: Bearer <token>
```

This can be, in certain cases, a stateless authorization mechanism. The server's protected routes will check for a valid JWT in the Authorization header, and if it's present, the user will be allowed to access protected resources. If the JWT contains the necessary data, the need to query the database for certain operations may be reduced, though this may not always be the case.

Note that if you send JWT tokens through HTTP headers, you should try to prevent them from getting too big. Some servers don't accept more than 8 KB in headers. If you are trying to embed too much information in a JWT token, like by including all the user's permissions, you may need an alternative solution, like <a href="https://auth0.com/fine-grained-authorization" style="color: blue;">Auth0 Fine-Grained Authorization</a>.

If the token is sent in the Authorization header, Cross-Origin Resource Sharing (CORS) won't be an issue as it doesn't use cookies.

The following diagram shows how a JWT is obtained and used to access APIs or resources:

![image](https://github.com/user-attachments/assets/2b8db2fb-8d5d-4f89-8bdb-a4eeac3709e2)

1. The application or client requests authorization to the authorization server. This is performed through one of the different authorization flows. For example, a typical OpenID 
   Connect compliant web application will go through the /oauth/authorize endpoint using the authorization code flow.
2. When the authorization is granted, the authorization server returns an access token to the application.
3. The application uses the access token to access a protected resource (like an API).

Do note that with signed tokens, all the information contained within the token is exposed to users or other parties, even though they are unable to change it. This means you should not put secret information within the token.


## Why should we use JSON Web Tokens?

Let's talk about the benefits of JSON Web Tokens (JWT) when compared to Simple Web Tokens (SWT) and Security Assertion Markup Language Tokens (SAML).

- **Size**: As JSON is less verbose than XML, when it is encoded its size is also smaller, making JWT more compact than SAML. This makes JWT a good choice to be passed in HTML and HTTP environments.
  
- **Security**: SWT can only be symmetrically signed by a shared secret using the HMAC algorithm. However, JWT and SAML tokens can use a public/private key pair in the form of a X.509 certificate for signing. Signing XML with XML Digital Signature without introducing obscure security holes is very difficult when compared to the simplicity of signing JSON.

- **Ease of use**: JSON parsers are common in most programming languages because they map directly to objects. Conversely, XML doesn't have a natural document-to-object mapping. This makes it easier to work with JWT than SAML assertions.

- **Usage**: JWT is used at Internet scale. This highlights the ease of client-side processing of the JSON Web token on multiple platforms, especially mobile.

- Regarding usage, JWT is used at Internet scale. This highlights the ease of client-side processing of the JSON Web token on multiple platforms, especially mobile.


## Comparison of the length of an encoded JWT and an encoded SAML is shown below
￼
￼![image](https://github.com/user-attachments/assets/6161d849-7bf3-4d31-8c6d-eb3b9adf9352)

```

You can now use the above `README.md` in your project or documentation.

## JWT Implementation in Java (Spring Boot)

### Dependencies (Maven)

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
```

### JWT Utility Class (Token Generation & Validation)

```java
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;

public class JwtUtil {
    private static final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 1000 * 60 * 60;  // 1 hour

    // Generate Token
    public static String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key)
                .compact();
    }

    // Validate Token
    public static Claims validateToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            throw new RuntimeException("Invalid Token");
        }
    }
}
```

### Controller (Login & Access Protected Resource)

```java
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class AuthController {

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        // Dummy check (Replace with DB verification)
        if ("user".equals(username) && "password".equals(password)) {
            return JwtUtil.generateToken(username);
        }
        throw new RuntimeException("Invalid Credentials");
    }

    @GetMapping("/protected")
    public String accessProtected(@RequestHeader("Authorization") String token) {
        String jwt = token.substring(7);  // Remove "Bearer "
        Claims claims = JwtUtil.validateToken(jwt);
        return "Hello " + claims.getSubject() + ", You have access to this resource!";
    }
}
```

---

## Testing the Implementation (Postman)

### 1. Login Endpoint:

- **POST /api/login**
  - Body: `{ "username": "user", "password": "password" }`
  - Response: `<JWT Token>`

### 2. Access Protected Route:

- **GET /api/protected**
  - Header: `Authorization: Bearer <Token>`
  - Response: `Hello user, You have access to this resource!`

---


## Understanding the "Bearer " Token Format

In JWT authentication, the token is often passed in the **Authorization** header of the HTTP request in the format:

```
Authorization: Bearer <jwt-token>
```

### Key Components:
- `"Bearer "`: This is a keyword used to indicate that the following part of the header is a Bearer token.
- `<jwt-token>`: This is the actual JWT token string, which is used for authentication.

### Why is the space important?

The string `"Bearer "` consists of **7 characters**:
1. `B` (1st character)
2. `e` (2nd character)
3. `a` (3rd character)
4. `r` (4th character)
5. `e` (5th character)
6. `r` (6th character)
7. **space** (7th character)

This space is important when extracting the token, as it separates the **"Bearer"** keyword from the actual token. 

### Token Extraction Logic:

The line:

```
if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
    // This checks if the header starts with "Bearer " (7 characters including the space)
    token = authorizationHeader.substring(7); // removes the "Bearer " part, leaving only the JWT token
}
```

checks if the `Authorization` header starts with the string `"Bearer "` (note the space after "Bearer"). The Bearer token scheme in HTTP headers uses the format:

```
Authorization: Bearer <jwt-token>
```

So, `"Bearer "` has **7 characters** (including the space), which ensures that the token is indeed a Bearer token and not some other type of token.

Once the header is confirmed to start with `"Bearer "`, the actual JWT token is extracted by removing the first 7 characters, like this:

```
token = authorizationHeader.substring(7); // removes "Bearer " from the header
```

For example, if the `Authorization` header is:

```
Authorization: Bearer your-jwt-token-here
```

The `substring(7)` function will extract the JWT token part:

```
your-jwt-token-here
```

### Conclusion:
Always make sure to check for the full `"Bearer "` string, including the **space**, to accurately extract the JWT token. This ensures the token is properly handled and validated in your application. By doing this, you are confirming that the token follows the correct Bearer format and can be used for authentication.

This version includes the detailed explanation about the `startsWith("Bearer ")` check and how the space is handled during token extraction.

---

## How it Works:

1. User logs in by sending credentials.
2. If valid, a JWT is generated and returned.
3. For protected routes, the JWT is passed in the `Authorization` header.
4. The server validates the token before granting access.

---

By following this guide, you can implement JWT-based authentication and authorization in a Spring Boot application.


This `ARTICLE` provides an in-depth overview of JWT, including its structure, usage, security, benefits, and a complete implementation example for Spring Boot.



---


## Click here to get in touch with me: 
<a href="https://github.com/Tech-Hubs" target="_blank"><b>PrabhatDevLab</b></a>, 
<a href="https://hugs-4-bugs.github.io/myResume/" target="_blank"><b>PrabhatKumar.com</b></a>, 
<a href="https://www.linkedin.com/in/prabhat-kumar-6963661a4/" target="_blank"><b>LinkedIn</b></a>, 
<a href="https://stackoverflow.com/users/19520484/prabhat-kumar" target="_blank"><b>Stackoverflow</b></a>, 
<a href="https://github.com/Hugs-4-Bugs" target="_blank"><b>GitHub</b></a>, 
<a href="https://leetcode.com/u/Hugs-2-Bugs/" target="_blank"><b>LeetCode</b></a>, 
<a href="https://www.hackerrank.com/profile/Prabhat_7250" target="_blank"><b>HackerRank</b></a>, 
<a href="https://www.geeksforgeeks.org/user/stealthy_prabhat/" target="_blank"><b>GeeksforGeeks</b></a>, 
<a href="https://hugs-4-bugs.github.io/AlgoByPrabhat/" target="_blank"><b>AlgoByPrabhat</b></a>, 
<a href="http://hugs-4-bugs.github.io/Sharma-AI/" target="_blank"><b>SHARMA AI</b></a>,  <a href="https://linktr.ee/_s_4_sharma" target="_blank"><b>About Me</b></a>, <a href="https://www.instagram.com/_s_4_sharma/" target="_blank"><b>Instagram</b></a>, <a href="https://x.com/kattyPrabhat" target="_blank"><b>Twitter</b></a>



<p>Happy Learning! 📚✨ Keep exploring and growing your knowledge! 🚀😊</p>
