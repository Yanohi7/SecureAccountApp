# SecureAccountApp

Лабораторна робота №6. Вебзастосунок для керування обліковими записами.
Стек: React, Vite, ASP.NET Core Web API, Entity Framework Core та SQLite.

## Запуск

Потрібні .NET 10 SDK і Node.js, сумісний з Vite 8.

У папці `Backend` запустіть `dotnet run --launch-profile http`.
У папці `Frontend` виконайте `npm ci`, потім `npm run dev -- --strictPort`.
Відкрийте http://localhost:5173. SQLite створює локальну базу під час першого запуску.

## Пошта та Google

Перед запуском бекенду задайте `SmtpSettings__SenderEmail` та
`SmtpSettings__Password` через змінні середовища. Для іншого SMTP-сервера
задайте `SmtpSettings__Server` та `SmtpSettings__Port`. Пошта потрібна для
активації акаунта, 2FA та відновлення пароля.

Для входу через Google задайте `GoogleAuth__ClientId` для клієнта типу
Web application. Додайте http://localhost:5173 до дозволених джерел JavaScript
у налаштуваннях цього клієнта.

Перший зареєстрований акаунт отримує роль адміністратора. Для доступу до
адмінпанелі після реєстрації паролем потрібно підтвердити пошту.
