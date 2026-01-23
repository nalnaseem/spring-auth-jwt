# JWT Authentication Service — Prerequisites, How to Run, and API Reference

A compact guide to run and use the Spring Boot JWT authentication service included in this repository. It documents prerequisites, optional Docker setup for SQL Server, configuration examples, build/run instructions, and the API endpoints with example requests and responses.

Checklist
- Prerequisites installed (Java 17, Maven)
- (Optional) SQL Server container ready or a DB configured
- `src/main/resources/application.properties` configured
- Build and run with Maven or the packaged artifact

---

## Prerequisites
- Java 17 JDK (project targets Java 17)
- Apache Maven 3.6+
- (Optional) Docker (if you want to run SQL Server in a container)
- (Optional) IDE with Lombok support — Lombok is provided as `provided` in `pom.xml`, enable annotation processing in your IDE

## Optional: Run SQL Server with Docker (Windows PowerShell)
If you don't have MS SQL Server available locally, start a dev container:

```powershell
docker run -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=StrongP@ssw0rd!" -p 1433:1433 --name mssql -d mcr.microsoft.com/mssql/server:2022-latest
```

Create the database (connect with sqlcmd):

```powershell
docker exec -it mssql /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "StrongP@ssw0rd!" -C
-- then in sqlcmd:
CREATE DATABASE jwt_auth_db;
GO
```

Notes:
- Change the password and port mapping for real environments.
- The container may take a few seconds to start.

## Configuration (example `src/main/resources/application.properties`)
Place or update these properties in `src/main/resources/application.properties` or use environment variables to override them.

```
# Server
server.port=8090

# Datasource (MS SQL Server example)
spring.datasource.url=jdbc:sqlserver://localhost:1433;databaseName=jwt_auth_db
spring.datasource.username=sa
spring.datasource.password=YourStrong!Passw0rd
spring.datasource.driver-class-name=com.microsoft.sqlserver.jdbc.SQLServerDriver

# JPA / Hibernate
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true

# JWT (example keys — replace in production)
jwt.secret=replace_with_a_secure_secret
jwt.accessTokenExpirationMs=3600000
jwt.refreshTokenExpirationMs=2592000000

# Localization (message bundles)
spring.messages.basename=messages

# Logging (optional)
logging.level.org.springframework=INFO
```

Assumptions: the project uses properties similar to the keys above — replace `jwt.*` with the actual keys used in your code if they differ.

## Build & Run

Run in development (recommended while coding):

```powershell
mvn spring-boot:run
```

Build the artifact and run the produced WAR/JAR:

```powershell
mvn clean package
java -jar target\jwt-0.0.1-SNAPSHOT.war
```

Override properties with environment variables (example):

```powershell
$env:SPRING_DATASOURCE_URL = "jdbc:sqlserver://localhost:1433;databaseName=jwt_auth_db"
mvn spring-boot:run
```

To run with a different Spring profile:

```powershell
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

## API Reference (base URL: http://localhost:8090)

Authentication uses JSON Web Tokens (JWT). The login endpoint returns an access token and a refresh token. Send the access token with `Authorization: Bearer <token>` to access protected endpoints.

Notes: endpoints below match the controllers in the project source. If your application context or base path differs, update the examples accordingly.

### 1) POST /v1/auth/login
- Purpose: Authenticate user and obtain JWT tokens
- Auth: none
- Request body: JSON — `LoginRequest`
  - username: string (required)
  - password: string (required)

Request example:

```http
POST /v1/auth/login HTTP/1.1
Content-Type: application/json

{
  "username": "user@example.com",
  "password": "secret"
}
```

Success response (200):

```json
{
  "accessToken": "eyJ...",
  "refreshToken": "eyJ...",
  "expiresInMs": 3600000
}
```

Errors:
- 400 Bad Request — validation errors or malformed JSON
- 401 Unauthorized — invalid credentials

---

### 2) POST /v1/auth/refresh
- Purpose: Exchange a refresh token for a new access token
- Auth: none
- Request body: JSON — `RefreshTokenRequest`
  - refreshToken: string (required)

Request example:

```http
POST /v1/auth/refresh HTTP/1.1
Content-Type: application/json

{
  "refreshToken": "eyJ..."
}
```

Success response (200) — same shape as the login response:

```json
{
  "accessToken": "eyJ...",
  "refreshToken": "eyJ...",
  "expiresInMs": 3600000
}
```

Errors:
- 400 Bad Request — validation errors
- 401 Unauthorized — invalid or expired refresh token

---

### 3) GET /test
- Purpose: Public health/test endpoint
- Auth: none
- Response: 200 OK — plain text `test`

Example:

```http
GET /test HTTP/1.1

# response body: test
```

### 4) GET /auth/test
- Purpose: Protected test endpoint
- Auth: required — `Authorization: Bearer <accessToken>`
- Response: 200 OK — plain text `you are authenticated`

Errors:
- 401 Unauthorized — missing or invalid token
- 403 Forbidden — access denied

Example:

```http
GET /auth/test HTTP/1.1
Authorization: Bearer eyJ...
```

## DTOs & Validation (key DTOs)

LoginRequest
- username: string
  - @NotNull(message = "{login.username.notnull}")
  - @NotBlank(message = "{login.username.notblank}")
- password: string
  - @NotNull(message = "{login.password.notnull}")
  - @NotBlank(message = "{login.password.notblank}")

RefreshTokenRequest
- refreshToken: string
  - @NotBlank(message = "{refresh.token.notblank}")

JwtTokenDto (response)
- accessToken: string
- refreshToken: string
- expiresInMs: long

Validation errors are returned as a structured `ApiValidationErrorResponse` containing a list of field errors (`field`, `message`).

## Error responses

General error wrapper (`ApiErrorResponse`) — fields typically included:
- httpStatus: HTTP status code
- path: request path
- message: resolved localized message
- timestamp: timestamp of the error

Validation example (400):

```json
{
  "httpStatus": 400,
  "path": "/v1/auth/login",
  "message": "Validation failed",
  "timestamp": "2026-01-23T12:00:00Z",
  "fieldErrors": [
    { "field": "username", "message": "must not be blank" }
  ]
}
```

Authentication error example (401):

```json
{
  "httpStatus": 401,
  "path": "/v1/auth/login",
  "message": "Invalid credentials",
  "timestamp": "2026-01-23T12:00:00Z"
}
```

## Troubleshooting & Notes
- Lombok: enable annotation processing in your IDE so generated code is visible.
- DB connection issues: verify `spring.datasource.url` / credentials and that the SQL Server container is running.
- JWT issues: ensure the `jwt.secret` is set and matches what the application expects; check token expiry settings.
- If you change message keys/locales, restart the application to reload bundles.

Useful classes for debugging: `JwtAuthFilter`, `AuthenticationController`, and the global exception handler (look under `com.alnaseem.jwt` package).

## Postman
A Postman collection may be included in the repository under `postman/` — import it to test endpoints quickly.

## License / Attribution
This project uses common open-source libraries (Spring Boot, Spring Security, Hibernate, Lombok, etc.). Use and adapt according to those libraries' licenses. Add your preferred license here.

---

If you want, I can also:
- Add curl examples for each endpoint in a separate `EXAMPLES.md` file
- Create a `application.properties.example` with safe placeholder values
- Add a short `CONTRIBUTING.md` with how to run and test locally
