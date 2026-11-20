# Security Specification — 백오 (Admin Auth + Prompt Library)

## 1. Data Invariants
1. Every document in `/prompts/{promptId}` must have a valid alphanumeric/underscore/hyphen ID (`<= 128` chars).
2. Every prompt document must contain strictly `['title', 'category', 'content', 'createdAt']` with no shadow or extra fields.
3. `title` must be a non-empty string (`1..120` chars).
4. `category` must be strictly one of `'사진 합성'`, `'스타일 변환'`, `'캐릭터·포스터'`.
5. `content` must be a non-empty string (`1..20000` chars) supporting long multi-line prompts over 1,000 characters.
6. `createdAt` must strictly equal `request.time` on create and remain immutable (`incoming().createdAt == existing().createdAt`) on update.
7. Public unauthenticated read access (`get`, `list`) is intentional so guests can browse, search, filter, view, and copy prompts without logging in (zero PII).
8. All write operations (`create`, `update`, `delete`) require a verified Google-authenticated admin (`request.auth.token.email == 'on741548@gmail.com' && request.auth.token.email_verified == true`).

## 2. Adversarial Payloads ("Dirty Dozen" Edge Cases)
1. Unauthenticated create/update/delete -> Rejected by `isAdmin()`.
2. Authenticated non-admin user (`other@gmail.com`) create/update/delete -> Rejected by `isAdmin()`.
3. Email spoofing (`email == 'on741548@gmail.com'`, `email_verified == false`) -> Rejected by `isAdmin()`.
4. Shadow field injection on create or update (`isAdmin: true`) -> Rejected by `keys().hasOnly(...)` and `affectedKeys().hasOnly(...)`.
5. Missing required field (`content` omitted) -> Rejected by `keys().hasAll(...)`.
6. Invalid category string (`"기타"`) -> Rejected by `category in [...]`.
7. Oversized `content` (> 20,000 chars) -> Rejected by `content.size() <= 20000`.
8. Empty or oversized `title` -> Rejected by `title.size() >= 1 && title.size() <= 120`.
9. Client-forged `createdAt` on create -> Rejected by `createdAt == request.time`.
10. Modifying `createdAt` during update -> Rejected by `incoming().createdAt == existing().createdAt` and `affectedKeys().hasOnly(['title', 'category', 'content'])`.
11. Invalid document ID containing special characters or > 128 chars -> Rejected by `isValidId(promptId)`.
12. Write to undeclared collection (`/users/123` or `/admins/123`) -> Rejected by default-deny catch-all.
