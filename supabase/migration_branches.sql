-- ============================================================================
-- JAI CHAN SPA — Stock Management : MULTI-BRANCH migration
-- Run ONCE in Supabase → SQL Editor → New query → paste → Run.
-- Idempotent & non-destructive: existing data is assigned to branch 'siam'.
-- Adds: branches table, per-branch stock/logs/adjustments/counts, branch-aware
--       RLS (staff see only their branch, managers see all), branch-aware RPC.
-- ============================================================================

-- ---------- BRANCHES ----------
create table if not exists public.branches (
  id         text primary key,
  name       text not null,
  sort       int  not null default 0,
  active     boolean not null default true,
  created_at timestamptz not null default now()
);
insert into public.branches(id,name,sort) values
  ('siam','Siam Discovery',1),
  ('amara','Amara Hotel',2),
  ('samyarn','Samyarn',3)
on conflict (id) do nothing;

alter table public.branches enable row level security;
drop policy if exists branches_read on public.branches;
create policy branches_read on public.branches for select to authenticated using (true);

-- ---------- PROFILES: home branch for staff ----------
alter table public.profiles add column if not exists branch_id text references public.branches(id);
update public.profiles set branch_id='siam' where branch_id is null;

-- ---------- BRANCH SCOPING on domain tables ----------
alter table public.products    add column if not exists branch_id text not null default 'siam' references public.branches(id);
alter table public.logs        add column if not exists branch_id text not null default 'siam' references public.branches(id);
alter table public.adjustments add column if not exists branch_id text not null default 'siam' references public.branches(id);
alter table public.counts      add column if not exists branch_id text not null default 'siam' references public.branches(id);

-- products are now keyed per (branch, sku) so the same SKU can live in many branches
alter table public.products drop constraint if exists products_pkey;
alter table public.products add primary key (branch_id, sku);

create index if not exists idx_logs_branch_date on public.logs(branch_id, date);
create index if not exists idx_adj_branch_ts    on public.adjustments(branch_id, ts desc);
create index if not exists idx_counts_branch     on public.counts(branch_id);

-- helper: the signed-in user's home branch
create or replace function public.my_branch()
returns text language sql stable security definer set search_path = public as $$
  select branch_id from public.profiles where id = auth.uid();
$$;

-- ---------- RLS (rewritten with branch scoping) ----------
-- products: read own branch (managers all); writes managers only via RPC
drop policy if exists products_read on public.products;
create policy products_read on public.products for select to authenticated
  using (public.is_manager() or branch_id = public.my_branch());
drop policy if exists products_write_mgr on public.products;
create policy products_write_mgr on public.products for all to authenticated
  using (public.is_manager()) with check (public.is_manager());

-- logs: read own branch (managers all); writes via RPC only
drop policy if exists logs_read on public.logs;
create policy logs_read on public.logs for select to authenticated
  using (public.is_manager() or branch_id = public.my_branch());

-- adjustments: read own branch (managers all); writes via RPC only
drop policy if exists adj_read on public.adjustments;
create policy adj_read on public.adjustments for select to authenticated
  using (public.is_manager() or branch_id = public.my_branch());

-- counts: read own branch; staff create/update OPEN drafts of their branch; close/delete = manager
drop policy if exists counts_read on public.counts;
create policy counts_read on public.counts for select to authenticated
  using (public.is_manager() or branch_id = public.my_branch());
drop policy if exists counts_insert on public.counts;
create policy counts_insert on public.counts for insert to authenticated
  with check (public.is_manager() or branch_id = public.my_branch());
drop policy if exists counts_update on public.counts;
create policy counts_update on public.counts for update to authenticated
  using (public.is_manager() or (branch_id = public.my_branch() and status = 'open'))
  with check (public.is_manager() or (branch_id = public.my_branch() and status = 'open'));
drop policy if exists counts_delete_mgr on public.counts;
create policy counts_delete_mgr on public.counts for delete to authenticated using (public.is_manager());

-- ============================================================================
-- RPC FUNCTIONS (branch-aware; drop old signatures first, then recreate)
-- ============================================================================
drop function if exists public.log_service(text,date,text,text,int,jsonb,jsonb);
drop function if exists public.adjust_stock(text,numeric,text);
drop function if exists public.save_product(jsonb,text);
drop function if exists public.delete_product(text);
drop function if exists public.import_all(jsonb);

-- log a day's service for a branch -> insert log + deduct that branch's stock
create or replace function public.log_service(
  p_branch text, p_id text, p_date date, p_service text, p_service_id text,
  p_count int, p_usage jsonb, p_choices jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare u jsonb;
begin
  if auth.uid() is null then raise exception 'not authenticated'; end if;
  if not (public.is_manager() or p_branch = public.my_branch()) then
    raise exception 'branch not allowed'; end if;
  insert into public.logs(id,branch_id,date,service,service_id,count,usage,choices,created_by)
  values (p_id,p_branch,p_date,p_service,p_service_id,p_count,
          coalesce(p_usage,'[]'::jsonb), coalesce(p_choices,'{}'::jsonb), auth.uid());
  for u in select value from jsonb_array_elements(coalesce(p_usage,'[]'::jsonb)) loop
    update public.products
       set stock = stock - (u->>'qty')::numeric, updated_at = now()
     where branch_id = p_branch and sku = u->>'sku';
  end loop;
end; $$;

-- void a log (MANAGER) -> restore that log's branch stock by snapshot + delete
create or replace function public.void_log(p_id text)
returns void language plpgsql security definer set search_path = public as $$
declare u jsonb; rec public.logs;
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  select * into rec from public.logs where id = p_id;
  if not found then return; end if;
  for u in select value from jsonb_array_elements(coalesce(rec.usage,'[]'::jsonb)) loop
    update public.products set stock = stock + (u->>'qty')::numeric, updated_at = now()
     where branch_id = rec.branch_id and sku = u->>'sku';
  end loop;
  delete from public.logs where id = p_id;
end; $$;

-- manual stock adjustment for a branch (MANAGER) -> audit row + set stock
create or replace function public.adjust_stock(p_branch text, p_sku text, p_to numeric, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare cur numeric; pname text;
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  select stock, name into cur, pname from public.products where branch_id = p_branch and sku = p_sku;
  if not found then raise exception 'product not found'; end if;
  if p_to <> cur then
    insert into public.adjustments(branch_id,sku,product_name,from_qty,to_qty,delta,reason,actor)
    values (p_branch, p_sku, pname, cur, p_to, p_to-cur, p_reason, auth.uid());
    update public.products set stock = p_to, updated_at = now() where branch_id = p_branch and sku = p_sku;
  end if;
end; $$;

-- upsert a product into a branch (MANAGER); logs an adjustment if stock changed
create or replace function public.save_product(p_branch text, p jsonb, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare cur numeric; existed boolean; v_sku text := p->>'sku';
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  select stock into cur from public.products where branch_id = p_branch and sku = v_sku;
  existed := found;
  insert into public.products(branch_id,sku,name,category,unit,cost,sachet_size,stock,min_stock,reorder_qty,
     monthly_usage,supplier_name,order_channel,order_url,contact,lead_time_days,pack_size,supplier_notes,updated_at)
  values (p_branch, v_sku, p->>'name', p->>'category', p->>'unit',
     coalesce((p->>'cost')::numeric,0), nullif(p->>'sachetSize','')::numeric,
     coalesce((p->>'stock')::numeric,0), coalesce((p->>'minStock')::numeric,0),
     coalesce((p->>'reorderQty')::numeric,0), coalesce((p->>'monthlyUsage')::numeric,0),
     coalesce(p->>'supplierName',''), coalesce(p->>'orderChannel',''), coalesce(p->>'orderUrl',''),
     coalesce(p->>'contact',''), nullif(p->>'leadTimeDays','')::int,
     coalesce(p->>'packSize',''), coalesce(p->>'supplierNotes',''), now())
  on conflict (branch_id,sku) do update set
     name=excluded.name, category=excluded.category, unit=excluded.unit, cost=excluded.cost,
     sachet_size=excluded.sachet_size, stock=excluded.stock, min_stock=excluded.min_stock,
     reorder_qty=excluded.reorder_qty, monthly_usage=excluded.monthly_usage,
     supplier_name=excluded.supplier_name, order_channel=excluded.order_channel,
     order_url=excluded.order_url, contact=excluded.contact, lead_time_days=excluded.lead_time_days,
     pack_size=excluded.pack_size, supplier_notes=excluded.supplier_notes, updated_at=now();
  if existed and cur is distinct from coalesce((p->>'stock')::numeric,0) then
    insert into public.adjustments(branch_id,sku,product_name,from_qty,to_qty,delta,reason,actor)
    values (p_branch, v_sku, p->>'name', cur, (p->>'stock')::numeric,
            (p->>'stock')::numeric - cur, coalesce(p_reason,'แก้ผ่านฟอร์มสินค้า'), auth.uid());
  end if;
end; $$;

create or replace function public.delete_product(p_branch text, p_sku text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  delete from public.products where branch_id = p_branch and sku = p_sku;
end; $$;

-- close a stock-count round (MANAGER) -> apply counted qty to the count's branch
create or replace function public.close_count(p_id text, p_result jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare rec public.counts; k text; v numeric; cur numeric; pname text;
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  select * into rec from public.counts where id = p_id;
  if not found or rec.status = 'closed' then return; end if;
  for k, v in select key, value::numeric from jsonb_each_text(rec.lines) loop
    select stock, name into cur, pname from public.products where branch_id = rec.branch_id and sku = k;
    if found and v <> cur then
      insert into public.adjustments(branch_id,sku,product_name,from_qty,to_qty,delta,reason,actor)
      values (rec.branch_id, k, pname, cur, v, v-cur, 'นับสต็อก '||coalesce(rec.label,''), auth.uid());
      update public.products set stock = v, updated_at = now() where branch_id = rec.branch_id and sku = k;
    end if;
  end loop;
  update public.counts set status='closed', closed_ts=now(), result=p_result where id = p_id;
end; $$;

-- one-time bulk import into a branch (MANAGER)
create or replace function public.import_all(p_branch text, p jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare it jsonb;
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  for it in select value from jsonb_array_elements(coalesce(p->'products','[]'::jsonb)) loop
    perform public.save_product(p_branch, it, 'นำเข้าครั้งแรก');
  end loop;
  for it in select value from jsonb_array_elements(coalesce(p->'services','[]'::jsonb)) loop
    insert into public.services(id,name,recipe)
    values (it->>'id', it->>'name', coalesce(it->'recipe','[]'::jsonb))
    on conflict (id) do update set name=excluded.name, recipe=excluded.recipe, updated_at=now();
  end loop;
  for it in select value from jsonb_array_elements(coalesce(p->'logs','[]'::jsonb)) loop
    insert into public.logs(id,branch_id,date,service,service_id,count,usage,choices)
    values (it->>'id', p_branch, (it->>'date')::date, it->>'service', it->>'serviceId',
            coalesce((it->>'count')::int,0), coalesce(it->'usage','[]'::jsonb), coalesce(it->'choices','{}'::jsonb))
    on conflict (id) do nothing;
  end loop;
  for it in select value from jsonb_array_elements(coalesce(p->'adjustments','[]'::jsonb)) loop
    insert into public.adjustments(branch_id,sku,product_name,from_qty,to_qty,delta,reason,ts)
    values (p_branch, it->>'sku', it->>'productName', (it->>'from')::numeric, (it->>'to')::numeric,
            (it->>'delta')::numeric, it->>'reason', coalesce((it->>'ts')::timestamptz, now()));
  end loop;
  for it in select value from jsonb_array_elements(coalesce(p->'counts','[]'::jsonb)) loop
    insert into public.counts(id,branch_id,period_key,round,label,deadline,status,counted_by,lines,result)
    values (it->>'id', p_branch, it->>'periodKey', coalesce((it->>'round')::int,1), it->>'label',
            nullif(it->>'deadline','')::date, coalesce(it->>'status','closed'),
            coalesce(it->>'countedBy',''), coalesce(it->'lines','{}'::jsonb), it->'result')
    on conflict (id) do nothing;
  end loop;
end; $$;

-- clone the product catalog from one branch into another (MANAGER); stock & usage reset to 0
create or replace function public.clone_catalog(p_from text, p_to text)
returns int language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  insert into public.products(branch_id,sku,name,category,unit,cost,sachet_size,stock,min_stock,reorder_qty,
     monthly_usage,supplier_name,order_channel,order_url,contact,lead_time_days,pack_size,supplier_notes)
  select p_to,sku,name,category,unit,cost,sachet_size,0,min_stock,reorder_qty,0,
     supplier_name,order_channel,order_url,contact,lead_time_days,pack_size,supplier_notes
  from public.products where branch_id = p_from
  on conflict (branch_id,sku) do nothing;
  get diagnostics n = row_count;
  return n;
end; $$;

-- create / rename a branch (MANAGER)
create or replace function public.save_branch(p_id text, p_name text, p_sort int)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_manager() then raise exception 'manager role required'; end if;
  insert into public.branches(id,name,sort) values (p_id, p_name, coalesce(p_sort,0))
  on conflict (id) do update set name=excluded.name, sort=excluded.sort;
end; $$;

-- ---------- GRANTS ----------
grant execute on function
  public.log_service(text,text,date,text,text,int,jsonb,jsonb),
  public.void_log(text),
  public.adjust_stock(text,text,numeric,text),
  public.save_product(text,jsonb,text),
  public.delete_product(text,text),
  public.save_service(jsonb),
  public.delete_service(text),
  public.close_count(text,jsonb),
  public.import_all(text,jsonb),
  public.clone_catalog(text,text),
  public.save_branch(text,text,int),
  public.is_manager(),
  public.my_branch()
to authenticated;

-- ============================================================================
-- AFTER RUNNING THIS:
--   • Existing data stays under branch 'siam' (nothing lost).
--   • Assign a staff member to a branch:
--       update public.profiles set branch_id='amara' where email='someone@jaichanspa.com';
--   • Managers automatically see ALL branches.
--   • Populate Amara/Samyarn: log in as manager → switch to that branch →
--       Settings → "คัดลอกแคตตาล็อกจาก Siam" (or use clone_catalog('siam','amara')).
-- ============================================================================
