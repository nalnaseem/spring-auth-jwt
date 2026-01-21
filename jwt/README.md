# Prerequisites & Running

Before running the application, make sure you have the following installed and configured:

Prerequisites
- Java 17 JDK (required) — the project is built with Java 17 (`<java.version>` in `pom.xml`).
- Apache Maven 3.6+ (used to build and run the app)
- (Optional) An IDE with Lombok support (install Lombok plugin and enable annotation processing)
- Database: Microsoft SQL Server (project includes `mssql-jdbc`); you can also configure an in-memory DB for development.

Create SQL Server with Docker

If you don't have a SQL Server instance available locally, you can start one with Docker and create the database used by this project. The commands below are for PowerShell on Windows.

1) Run the SQL Server container (this will pull the image if needed):

```powershell
docker run -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=StrongP@ssw0rd!" -p 1433:1433 --name mssql -d mcr.microsoft.com/mssql/server:2022-latest
```

2) Open an interactive sqlcmd shell and connect as `sa` (the `-C` option forces encryption; remove if not required in your environment):

```powershell
docker exec -it mssql /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "StrongP@ssw0rd!" -C
```

3) Create the database and exit:

```sql
CREATE DATABASE jwt_auth_db;
GO
```

4) Verify the database exists (run inside `sqlcmd`):

```sql
SELECT name FROM sys.databases WHERE name = 'jwt_auth_db';
GO
```

Notes & safety
- The example uses a strong but example password. In real environments, pick a secure password and avoid committing credentials to source control.
- Port 1433 is mapped to the host; if you already have a SQL Server running on the host, change the host port mapping (for example `-p 1434:1433`) and update `spring.datasource.url` accordingly.
- On first start, the container may take a moment to initialize SQL Server; if `sqlcmd` fails to connect immediately, wait a few seconds and retry.

Recommended `application.properties` (example values - put these in `src/main/resources/application.properties` or use environment variables):

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
```

Build & run (PowerShell commands)

- Run with Maven (useful for development):

```
mvn spring-boot:run
```

- Run the generated artifact (WAR) after packaging:

```
java -jar target\jwt-0.0.1-SNAPSHOT.war
```


Notes
- Lombok: since Lombok is declared as `provided` in `pom.xml`, make sure your IDE has the Lombok plugin and annotation processing enabled so generated getters/setters/builders are recognized at compile time and in the editor.
- Environment variables: you can override `application.properties` values using environment variables (for example `SPRING_DATASOURCE_URL`) or pass `-D` properties on the command line (for example `-Dspring.profiles.active=dev`).

---

# JWT Authentication Service (API Reference)

This README lists all HTTP endpoints in this project, request/response DTOs, validation rules, example requests, and the common error responses.

Base URL (default for local run):
- http://localhost:8090

Authentication: JSON Web Tokens (JWT)
- Login returns an access token and a refresh token (see `JwtTokenDto`). Use the access token in the `Authorization: Bearer <token>` header for protected endpoints.

Endpoints
---------

1) POST /v1/auth/login
- Controller: `AuthenticationController`
- Purpose: Authenticate user and obtain JWT tokens
- Auth: no
- Request (JSON body): `LoginRequest`
  - username: string (required, not null, not blank)
  - password: string (required, not null, not blank)
- Success (200 OK): `JwtTokenDto`
  - accessToken: string
  - refreshToken: string
  - expiresInMs: long
- Possible errors:
  - 400 Bad Request — validation errors (missing fields, malformed JSON)
  - 401 Unauthorized — invalid credentials (handled as `InvalidCredentialsException`)

Example request:
```
POST /v1/auth/login
Content-Type: application/json

{
  "username": "user@example.com",
  "password": "secret"
}
```

Example success response:
```
200 OK
{
  "accessToken": "eyJ...",
  "refreshToken": "eyJ...",
  "expiresInMs": 3600000
}
```

---

2) POST /v1/auth/refresh
- Controller: `AuthenticationController`
- Purpose: Exchange a refresh token for a new access token (and possibly a new refresh token)
- Auth: no
- Request (JSON body): `RefreshTokenRequest`
  - refreshToken: string (required, not blank)
- Success (200 OK): `JwtTokenDto`
- Possible errors:
  - 400 Bad Request — validation errors or malformed JSON
  - 401 Unauthorized — invalid or expired refresh token

Example request:
```
POST /v1/auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJ..."
}
```

---

3) GET /test
- Controller: `TestController`
- Purpose: Public health/test endpoint
- Auth: no
- Success (200 OK): plain text body `test`

4) GET /auth/test
- Controller: `TestController`
- Purpose: A protected test endpoint that requires a valid JWT
- Auth: yes — send `Authorization: Bearer <accessToken>`
- Success (200 OK): plain text `you are authenticated`
- Possible errors:
  - 401 Unauthorized — missing or invalid token
  - 403 Forbidden — access denied

Example request (protected):
```
GET /auth/test
Authorization: Bearer eyJ...
```

DTOs and Validation
-------------------

`LoginRequest` (request body for `/v1/auth/login`)
- username: string
  - @NotNull(message = "{login.username.notnull}")
  - @NotBlank(message = "{login.username.notblank}")
- password: string
  - @NotNull(message = "{login.password.notnull}")
  - @NotBlank(message = "{login.password.notblank}")

`RefreshTokenRequest` (request body for `/v1/auth/refresh`)
- refreshToken: string
  - @NotBlank(message = "{refresh.token.notblank}")

`JwtTokenDto` (successful authentication response)
- accessToken: string
- refreshToken: string
- expiresInMs: long

Error Responses
---------------
General error wrapper: `ApiErrorResponse` (used by global exception handler)
- httpStatus: HTTP status (numeric / enum)
- path: request URI
- message: localized message key resolved to message text
- timestamp: date/time

Validation errors: `ApiValidationErrorResponse` extends `ApiErrorResponse` and includes `fieldErrors` list of `{ field, message }` objects for field-level errors.

Common handled exceptions (global `ControllerAdvice` in `ExceptionHandling`)
- `InvalidCredentialsException` -> 401 Unauthorized
- `JwtExpiredException` -> 401 Unauthorized
- `AuthorizationDeniedException` / `AccessDeniedException` -> 403 Forbidden
- `HttpRequestMethodNotSupportedException` -> 405 Method Not Allowed
- `HttpMessageNotReadableException` -> 400 Bad Request (malformed JSON)
- `MethodArgumentNotValidException` -> 400 Bad Request (validation errors)
- `DataIntegrityViolationException`, `ConstraintViolationException`, `InvalidDataAccessResourceUsageException` -> 500 Internal Server Error

Notes & Usage
-------------
- Server default port in this project: 8090 (verify `application.properties` for overrides).
- To call protected endpoints add the header: `Authorization: Bearer <accessToken>`
---

