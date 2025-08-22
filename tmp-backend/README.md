# tmp-backend (Node.js, Express) — JWT + Refresh (HttpOnly cookie)

## Run
```bash
npm i
npm run dev  # or npm start
```
- Default: `http://localhost:3000`
- Angular origin allowed: `http://localhost:4200` (change in `.env`)

## Endpoints
- POST `/auth/login`    -> body `{ email, password }`
- POST `/auth/refresh`  -> uses `refresh_token` cookie
- POST `/auth/logout`   -> clears cookie
- GET  `/api/profile`   -> protected example (needs `Authorization: Bearer <access>`)

## Users
Edit `config/users.json`:

```json
{
  "users": [
    { "id": "1", "email": "test@example.com", "passwordHash": "<bcrypt>", "roles": ["user"] }
  ]
}
```

Generate bcrypt hash (Node REPL):
```js
// in project folder
node -e "import('bcryptjs').then(async b=>{console.log(await b.hash('YourPass123!',10))})"
```

## CSRF
- Sends `XSRF-TOKEN` cookie for Angular HttpClientXsrfModule (readable).
- For demo, `/auth/*` routes do not enforce CSRF; set up stricter checks in production.




## อยากเพิ่มผู้ใช้ใหม่ → สร้าง bcrypt hash ง่าย ๆ: set password  Passw0rd!
## node -e "import('bcryptjs').then(async b=>{console.log(await b.hash('YourPass123!',10))})"
