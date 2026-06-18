# JAI CHAN SPA — Stock Management (Cloud / Supabase)

Stock, recipes, daily service usage, stock-count rounds, and reorder — now with a
**real backend (Supabase Postgres) and real authentication**. Frontend stays static
on GitHub Pages; all stock-affecting actions are enforced **server-side** by role.

- **Live:** https://jaichanspa-admin.github.io/Stock-Management/
- **Roles:** `manager` (full control) · `staff` (daily entry + stock counting only)

---

## Architecture

```
GitHub Pages (index.html, static)  ──►  Supabase
                                         ├─ Auth (email + password)
                                         ├─ Postgres (products, services, logs,
                                         │            adjustments, counts, profiles)
                                         └─ RLS + RPC  ← permissions enforced here
```

Why this shape: GitHub Pages can only serve static files, so the backend lives in
Supabase (managed — no server to run). Manager-only actions (edit stock/products/
recipes, void logs, close counts, import) are blocked in the database itself, not
just in the UI. The previous client-side PIN is **removed**.

---

## One-time setup (~5 minutes)

1. **Create a Supabase project** → https://supabase.com (free tier is fine).

2. **Create the database**
   Supabase → **SQL Editor → New query** → paste all of
   [`supabase/schema.sql`](supabase/schema.sql) → **Run**.

3. **Enable email login**
   Authentication → **Providers → Email: ON**.
   For internal staff, turn **"Confirm email" OFF** (or confirm users manually).

4. **Create users & make yourself manager**
   Authentication → **Users → Add user** (one per staff member).
   Then in SQL Editor:
   ```sql
   update public.profiles set role='manager'
   where email='Manager.jaichan@jaichanspa.com';
   ```
   Everyone else stays `staff` automatically.

5. **Connect the app**
   Edit [`config.js`](config.js) with your **Project URL** and **anon public key**
   (Supabase → Project Settings → API), then commit/push.

6. **Import existing data (one time)**
   Open the app → log in as manager → **ตั้งค่า → "นำเข้าข้อมูลขึ้นคลาวด์ครั้งแรก"**
   and pick your old `jaichan_stock_*.json` export. (Or skip to start fresh from seed.)

---

## Day-to-day

- **Staff:** log in → **บันทึกบริการ** each day; do **นับสต็อก** before the 10th & 20th.
- **Manager:** approve stock adjustments, edit products/recipes, **close** count rounds,
  review the reorder list, manage users.

To add/remove staff later: Supabase → Authentication → Users. To change a role:
```sql
update public.profiles set role='staff' where email='someone@jaichanspa.com';
```

## Security notes

- The anon key in `config.js` is **public by design**; RLS is the real guard.
- Never put the `service_role` secret key in the frontend.
- All manual stock changes are written to an **audit log** with the acting user.
