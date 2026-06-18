-- ============================================================================
-- JAI CHAN SPA — Stock Management : Supabase schema + RLS + RPC
-- Run ONCE in Supabase → SQL Editor → New query → paste → Run.
-- Security model:
--   • Real auth via Supabase Auth (email + password).
--   • Roles in public.profiles (manager | staff), enforced server-side by RLS.
--   • Stock-affecting writes go through SECURITY DEFINER functions that check role,
--     so staff CANNOT manually edit stock / products / services / void logs.
--   • Daily service logging (deducts stock) is allowed for any signed-in user.
-- ============================================================================

-- ---------- PROFILES (per-user role) ----------------------------------------
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  email      text,
  role       text not null default 'staff' check (role in ('manager','staff')),
  created_at timestamptz not null default now()
);

-- auto-create a profile (role=staff) whenever a user signs up
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles(id, email, role)
  values (new.id, new.email, 'staff')
  on conflict (id) do nothing;
  return new;
end; $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- helper: is the current user a manager?
create or replace function public.is_manager()
returns boolean language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.profiles where id = auth.uid() and role = 'manager');
$$;

-- ---------- DOMAIN TABLES ----------------------------------------------------
create table if not exists public.products (
  sku            text primary key,
  name           text not null,
  category       text,
  unit           text,
  cost           numeric not null default 0,
  sachet_size    numeric,
  stock          numeric not null default 0,
  min_stock      numeric not null default 0,
  reorder_qty    numeric not null default 0,
  monthly_usage  numeric not null default 0,
  supplier_name  text default '',
  order_channel  text default '',
  order_url      text default '',
  contact        text default '',
  lead_time_days int,
  pack_size      text default '',
  supplier_notes text default '',
  updated_at     timestamptz not null default now()
);

create table if not exists public.services (
  id         text primary key,
  name       text not null,
  recipe     jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists public.logs (
  id         text primary key,
  date       date not null,
  service    text not null,
  service_id text,
  count      int  not null,
  usage      jsonb not null default '[]'::jsonb,   -- snapshot: [{sku,qty,cost}]
  choices    jsonb default '{}'::jsonb,
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now()
);

create table if not exists public.adjustments (
  id           uuid primary key default gen_random_uuid(),
  ts           timestamptz not null default now(),
  sku          text,
  product_name text,
  from_qty     numeric,
  to_qty       numeric,
  delta        numeric,
  reason       text,
  actor        uuid default auth.uid()
);

create table if not exists public.counts (
  id          text primary key,
  period_key  text not null,
  round       int  not null,
  label       text,
  deadline    date,
  status      text not null default 'open',
  started_ts  timestamptz default now(),
  closed_ts   timestamptz,
  counted_by  text default '',
  lines       jsonb not null default '{}'::jsonb,   -- {sku: countedQty}
  result      jsonb,
  created_by  uuid default auth.uid()
);

-- ---------- ROW LEVEL SECURITY ----------------------------------------------
alter table public.profiles    enable row level security;
alter table public.products    enable row level security;
alter table public.services    enable row level security;
alter table public.logs        enable row level security;
alter table public.adjustments enable row level security;
alter table public.counts      enable row level security;

-- profiles: any signed-in user can read; only managers may change roles
drop policy if exists profiles_read on public.profiles;
create policy profiles_read on public.profiles for select to authenticated using (true);
drop policy if exists profiles_update_mgr on public.profiles;
create policy profiles_update_mgr on public.profiles for update to authenticated
  using (public.is_manager()) with check (public.is_manager());

-- products: read all; direct writes managers only (deductions happen via RPC)
drop policy if exists products_read on public.products;
create policy products_read on public.products for select to authenticated using (true);
drop policy if exists products_write_mgr on public.products;
create policy products_write_mgr on public.products for all to authenticated
  using (public.is_manager()) with check (public.is_manager());

-- services: read all; writes managers only
drop policy if exists services_read on public.services;
create policy services_read on public.services for select to authenticated using (true);
drop policy if exists services_write_mgr on public.services;
create policy services_write_mgr on public.services for all to authenticated
  using (public.is_manager()) with check (public.is_manager());

-- logs: read all; inserts/deletes only via RPC (no direct write policy => denied)
drop policy if exists logs_read on public.logs;
create policy logs_read on public.logs for select to authenticated using (true);

-- adjustments: read all; writes only via RPC
drop policy if exists adj_read on public.adjustments;
create policy adj_read on public.adjustments for select to authenticated using (true);

-- counts: read all; staff may create/update OPEN drafts; closing & delete = manager
drop policy if exists counts_read on public.counts;
create policy counts_read on public.counts for select to authenticated using (true);
drop policy if exists counts_insert on public.counts;
create policy counts_insert on public.counts for insert to authenticated with check (true);
drop policy if exists counts_update on public.counts;
create policy counts_update on public.counts for update to authenticated
  using (status = 'open')
  with check (public.is_manager() or status = 'open');   -- staff cannot flip to 'closed'
drop policy if exists counts_delete_mgr on public.counts;
create policy counts_delete_mgr on public.counts for delete to authenticated using (public.is_manager());

-- ============================================================================
-- RPC FUNCTIONS (business logic + server-side permission checks)
-- ============================================================================

-- log a day's service (any signed-in user) -> insert log + deduct stock atomically
create or replace function public.log_service(
  p_id text, p_date date, p_service text, p_service_id text,
  p_count int, p_usage jsonb, p_choices jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare u jsonb;
begin
  if auth.uid() is null then raise exception 'not authenticated'; end if;
  insert into public.logs(id,date,service,service_id,count,usage,choices,created_by)
  values (p_id,p_date,p_service,p_service_id,p_count,
          coalesce(p_usage,'[]'::jsonb), coalesce(p_choices,'{}'::jsonb), auth.uid());
  for u in select value from jsonb_array_elements(coalesce(p_usage,'[]'::jsonb)) loop
    update public.products
       set stock = stock - (u->>'qty')::numeric, updated_at = now()
     where sku = u->>'sku';
  end loop;
end; $$;

-- void a log (MANAGER) -> restore stock by snapshot + delete log
create or replace function public.void_log(p_id text)
returns void language plpgsql security definer set search_path = public as $$
declare u jsonb; rec public.logs;
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  select * into rec from public.logs where id = p_id;
  if not found then return; end if;
  for u in select value from jsonb_array_elements(coalesce(rec.usage,'[]'::jsonb)) loop
    update public.products set stock = stock + (u->>'qty')::numeric, updated_at = now()
     where sku = u->>'sku';
  end loop;
  delete from public.logs where id = p_id;
end; $$;

-- manual stock adjustment (MANAGER) -> writes audit row + sets stock
create or replace function public.adjust_stock(p_sku text, p_to numeric, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare cur numeric; pname text;
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  select stock, name into cur, pname from public.products where sku = p_sku;
  if not found then raise exception 'product not found'; end if;
  if p_to <> cur then
    insert into public.adjustments(sku,product_name,from_qty,to_qty,delta,reason,actor)
    values (p_sku, pname, cur, p_to, p_to-cur, p_reason, auth.uid());
    update public.products set stock = p_to, updated_at = now() where sku = p_sku;
  end if;
end; $$;

-- upsert a product (MANAGER); logs an adjustment if stock changed on an existing item
create or replace function public.save_product(p jsonb, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare cur numeric; existed boolean; v_sku text := p->>'sku';
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  select stock into cur from public.products where sku = v_sku;
  existed := found;
  insert into public.products(sku,name,category,unit,cost,sachet_size,stock,min_stock,reorder_qty,
     monthly_usage,supplier_name,order_channel,order_url,contact,lead_time_days,pack_size,supplier_notes,updated_at)
  values (v_sku, p->>'name', p->>'category', p->>'unit',
     coalesce((p->>'cost')::numeric,0), nullif(p->>'sachetSize','')::numeric,
     coalesce((p->>'stock')::numeric,0), coalesce((p->>'minStock')::numeric,0),
     coalesce((p->>'reorderQty')::numeric,0), coalesce((p->>'monthlyUsage')::numeric,0),
     coalesce(p->>'supplierName',''), coalesce(p->>'orderChannel',''), coalesce(p->>'orderUrl',''),
     coalesce(p->>'contact',''), nullif(p->>'leadTimeDays','')::int,
     coalesce(p->>'packSize',''), coalesce(p->>'supplierNotes',''), now())
  on conflict (sku) do update set
     name=excluded.name, category=excluded.category, unit=excluded.unit, cost=excluded.cost,
     sachet_size=excluded.sachet_size, stock=excluded.stock, min_stock=excluded.min_stock,
     reorder_qty=excluded.reorder_qty, monthly_usage=excluded.monthly_usage,
     supplier_name=excluded.supplier_name, order_channel=excluded.order_channel,
     order_url=excluded.order_url, contact=excluded.contact, lead_time_days=excluded.lead_time_days,
     pack_size=excluded.pack_size, supplier_notes=excluded.supplier_notes, updated_at=now();
  if existed and cur is distinct from coalesce((p->>'stock')::numeric,0) then
    insert into public.adjustments(sku,product_name,from_qty,to_qty,delta,reason,actor)
    values (v_sku, p->>'name', cur, (p->>'stock')::numeric,
            (p->>'stock')::numeric - cur, coalesce(p_reason,'แก้ผ่านฟอร์มสินค้า'), auth.uid());
  end if;
end; $$;

create or replace function public.delete_product(p_sku text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  delete from public.products where sku = p_sku;
end; $$;

create or replace function public.save_service(p jsonb)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  insert into public.services(id,name,recipe,updated_at)
  values (p->>'id', p->>'name', coalesce(p->'recipe','[]'::jsonb), now())
  on conflict (id) do update set name=excluded.name, recipe=excluded.recipe, updated_at=now();
end; $$;

create or replace function public.delete_service(p_id text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  delete from public.services where id = p_id;
end; $$;

-- close a stock-count round (MANAGER) -> apply counted qty, write adjustments, store result
create or replace function public.close_count(p_id text, p_result jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare rec public.counts; k text; v numeric; cur numeric; pname text;
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  select * into rec from public.counts where id = p_id;
  if not found or rec.status = 'closed' then return; end if;
  for k, v in select key, value::numeric from jsonb_each_text(rec.lines) loop
    select stock, name into cur, pname from public.products where sku = k;
    if found and v <> cur then
      insert into public.adjustments(sku,product_name,from_qty,to_qty,delta,reason,actor)
      values (k, pname, cur, v, v-cur, 'นับสต็อก '||coalesce(rec.label,''), auth.uid());
      update public.products set stock = v, updated_at = now() where sku = k;
    end if;
  end loop;
  update public.counts set status='closed', closed_ts=now(), result=p_result where id = p_id;
end; $$;

-- one-time bulk import from the old LocalStorage export (MANAGER)
create or replace function public.import_all(p jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare it jsonb;
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  for it in select value from jsonb_array_elements(coalesce(p->'products','[]'::jsonb)) loop
    perform public.save_product(it, 'นำเข้าครั้งแรก');
  end loop;
  for it in select value from jsonb_array_elements(coalesce(p->'services','[]'::jsonb)) loop
    insert into public.services(id,name,recipe)
    values (it->>'id', it->>'name', coalesce(it->'recipe','[]'::jsonb))
    on conflict (id) do update set name=excluded.name, recipe=excluded.recipe, updated_at=now();
  end loop;
  for it in select value from jsonb_array_elements(coalesce(p->'logs','[]'::jsonb)) loop
    insert into public.logs(id,date,service,service_id,count,usage,choices)
    values (it->>'id', (it->>'date')::date, it->>'service', it->>'serviceId',
            coalesce((it->>'count')::int,0), coalesce(it->'usage','[]'::jsonb), coalesce(it->'choices','{}'::jsonb))
    on conflict (id) do nothing;
  end loop;
  for it in select value from jsonb_array_elements(coalesce(p->'adjustments','[]'::jsonb)) loop
    insert into public.adjustments(sku,product_name,from_qty,to_qty,delta,reason,ts)
    values (it->>'sku', it->>'productName', (it->>'from')::numeric, (it->>'to')::numeric,
            (it->>'delta')::numeric, it->>'reason', coalesce((it->>'ts')::timestamptz, now()));
  end loop;
  for it in select value from jsonb_array_elements(coalesce(p->'counts','[]'::jsonb)) loop
    insert into public.counts(id,period_key,round,label,deadline,status,counted_by,lines,result)
    values (it->>'id', it->>'periodKey', coalesce((it->>'round')::int,1), it->>'label',
            nullif(it->>'deadline','')::date, coalesce(it->>'status','closed'),
            coalesce(it->>'countedBy',''), coalesce(it->'lines','{}'::jsonb), it->'result')
    on conflict (id) do nothing;
  end loop;
end; $$;

-- allow signed-in users to call the RPCs (role checks happen inside)
grant execute on function
  public.log_service(text,date,text,text,int,jsonb,jsonb),
  public.void_log(text),
  public.adjust_stock(text,numeric,text),
  public.save_product(jsonb,text),
  public.delete_product(text),
  public.save_service(jsonb),
  public.delete_service(text),
  public.close_count(text,jsonb),
  public.import_all(jsonb),
  public.is_manager()
to authenticated;

-- ============================================================================
-- AFTER RUNNING THIS:
--   1) Authentication → Providers → Email: ON (turn OFF "Confirm email" for
--      internal staff accounts, or confirm them manually).
--   2) Create your users (Authentication → Users → Add user).
--   3) Promote yourself to manager:
--        update public.profiles set role='manager' where email='Manager.jaichan@jaichanspa.com';
--   4) Put your Project URL + anon key into config.js (see README).
--   5) Open the app, log in as manager, Settings → "นำเข้าข้อมูลขึ้นคลาวด์ครั้งแรก".
-- ============================================================================
