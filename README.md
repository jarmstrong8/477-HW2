# Secure Login for OWASP Juice Shop

A login page and API built to resist the attacks OWASP Juice Shop is deliberately
vulnerable to: SQL injection, cross-site scripting (XSS), and authentication bypass.
The front end is plain HTML/JS; the back end is Node.js + Express (the same stack
Juice Shop uses) with SQLite.

## Requirements

- Node.js 18 or newer
- npm

## Getting started

```bash
npm install
node create-user.js you@juice.sh yourpassword   # create an account
npm start                                        # http://localhost:3000
```

To use a different port: `PORT=8080 npm start`.

There is no registration page, so accounts are created with `create-user.js`. It applies
the same validation as the login form and stores only a bcrypt hash of the password.

## Project structure

| File | Purpose |
|---|---|
| `public/login.html` | Login form (email + password) and a logged-in view with a logout button |
| `public/login.js` | Client-side validation (`validateLogin`) and calls to the API |
| `public/login.css` | Styling |
| `server.js` | Express server: validation, login, sessions, security headers |
| `create-user.js` | Command-line tool for adding accounts |
| `users.db` | SQLite database (created automatically on first run) |

## Validation

The same rules run in the browser (`public/login.js`) and on the server (`server.js`):

- The email must contain `@`, look like `name@domain.tld`, be at most 254 characters,
  and contain no spaces, quotes, backticks, or `<` `>`.
- The password must be 8–128 characters.

The browser check only gives the user quick feedback. Anyone can skip it with curl,
Burp Suite, or the browser dev tools, so the server repeats every check and never
trusts the client.

## API

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/login` | Body `{"email": "...", "password": "..."}` (JSON only). Sets the session cookie. |
| `GET` | `/api/me` | Returns the logged-in user's email and role, or `401`. |
| `POST` | `/api/logout` | Ends the session on the server and clears the cookie. |

| Status | Meaning |
|---|---|
| `200` | Success |
| `400` | Validation failed or malformed JSON |
| `401` | Wrong email/password, or not logged in |
| `415` | Request body was not `application/json` |
| `429` | Too many failed login attempts |

## Security measures

### SQL injection

Every query uses prepared statements with `?` placeholders, so user input is bound as
data and never becomes part of the SQL. Juice Shop's own login builds its query by
joining strings, which is why `' OR 1=1--` logs you in as admin there. The server also
rejects quote characters in emails.

### Cross-site scripting (XSS)

- Text is written into the page with `textContent`, never `innerHTML`, so markup is
  shown as text instead of running.
- A strict Content-Security-Policy (set with `helmet`) only allows scripts and styles
  from this site. Inline `<script>` tags and `onerror=` handlers are blocked.
- The HTML has no inline scripts or styles, so the strict policy doesn't break the page.

### Authentication bypass and session security

- Login status comes only from a random 256-bit session token stored on the server.
  Nothing the client sends (headers, body fields, a made-up token) can log someone in.
- The session cookie is `HttpOnly` (scripts can't read it), `Secure` (HTTPS only), and
  `SameSite=Strict` (not sent with cross-site requests).
- Each login gets a fresh token (prevents session fixation). Logout deletes the session
  on the server, not just the cookie.
- Sessions expire after 30 minutes of inactivity.

### Passwords and brute force

- Passwords are hashed with bcrypt (cost 12). Juice Shop stores unsalted MD5.
- Each IP gets 5 failed login attempts per 15 minutes; successful logins don't count.
- A wrong password and an unknown email get the same message ("Invalid email or
  password."). Unknown emails are still checked against a dummy bcrypt hash, so both
  cases take about the same time and attackers can't tell which emails have accounts.

### Other

- **CSRF:** the login endpoint only accepts `application/json`, which a cross-site HTML
  form can't send, and the session cookie is `SameSite=Strict`.
- **Type checks:** the server rejects any email or password that isn't a plain string,
  which blocks payloads like `{"email": {"$ne": ""}}`.
- **Error handling:** clients get generic messages. Stack traces and SQL errors are only
  logged on the server.
- **Request size:** JSON bodies are limited to 10 KB.

## Testing the defenses

With the server running and an account created:

```bash
# Normal login: 200, sets an HttpOnly cookie
curl -i -X POST localhost:3000/api/login -H 'Content-Type: application/json' \
  -d '{"email":"you@juice.sh","password":"yourpassword"}'

# SQL injection bypass attempt: 400
curl -X POST localhost:3000/api/login -H 'Content-Type: application/json' \
  -d "{\"email\":\"' OR 1=1--\",\"password\":\"anything1\"}"

# Object injection: 400
curl -X POST localhost:3000/api/login -H 'Content-Type: application/json' \
  -d '{"email":{"$ne":""},"password":{"$ne":""}}'

# Made-up session cookie: 401
curl localhost:3000/api/me -H 'Cookie: sid=deadbeef'

# Form-encoded (CSRF-style) request: 415
curl -X POST localhost:3000/api/login -d 'email=a@b.co&password=aaaaaaaa'
```

Run the wrong-password request six times in a row and the sixth returns `429`.

## Limitations

- Sessions are kept in memory, so restarting the server logs everyone out. A production
  setup would use a persistent store such as Redis.
- The `Secure` cookie needs HTTPS. Browsers make an exception for `http://localhost`,
  but a real deployment must use HTTPS.
- This is a standalone app. To add it to Juice Shop itself, apply the same patterns in
  Juice Shop's Angular login component and its `/rest/user/login` route.
