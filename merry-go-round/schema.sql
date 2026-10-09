-- =====================================================================
-- MERRY-GO-ROUND NUMBER SELECTOR: run once in Supabase > SQL Editor.
-- It recreates the tables, so earlier test data is deleted.
-- =====================================================================

-- clean up earlier versions
drop table if exists picks, settings, admin_settings, members, audit_log, admins cascade;
drop function if exists get_state(), claim(text,int), admin_ok(text), admin_list(text),
  admin_save(text,text,int,text,boolean,boolean), admin_remove(text,int), admin_reset(text), admin_set_password(text,text);

-- ---------- tables ----------
create table admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);

create table members (
  id              uuid primary key default gen_random_uuid(),
  name            text not null check (length(trim(name)) between 1 and 60),
  contact         text check (length(contact) <= 120),
  code_hash       text not null unique,                        -- only the hash of the access code is stored
  assigned_number int  unique check (assigned_number between 1 and 4),  -- DB guarantees a number is used once
  selected_at     timestamptz,
  invite_used     boolean not null default false,
  created_at      timestamptz not null default now()
);
create unique index members_name_unique on members (lower(trim(name)));   -- no duplicate members

create table audit_log (
  id     bigint generated always as identity primary key,
  at     timestamptz not null default now(),
  actor  text not null,
  action text not null,
  detail text
);

-- Row Level Security: the public has NO direct table access. Only logged-in admins can read.
alter table admins    enable row level security;
alter table members   enable row level security;
alter table audit_log enable row level security;

create or replace function is_admin() returns boolean
language sql stable security definer set search_path = public as
$$ select exists (select 1 from admins where user_id = auth.uid()) $$;

create policy "admins read members" on members   for select to authenticated using (is_admin());
create policy "admins read audit"   on audit_log for select to authenticated using (is_admin());

-- live updates for the admin dashboard
do $$ begin alter publication supabase_realtime add table members;
exception when others then null; end $$;

-- ---------- helpers ----------
create or replace function code_hash(t text) returns text
language sql immutable as
$$ select encode(sha256(convert_to(upper(regexp_replace(coalesce(t,''),'[^A-Za-z0-9]','','g')),'utf8')),'hex') $$;

create or replace function new_code() returns text
language sql volatile as
$$ select upper(substr(replace(gen_random_uuid()::text,'-',''),1,12)) $$;

-- ---------- public functions (members) ----------

-- counts only: never reveals who has which number
create or replace function public_progress() returns json
language sql security definer set search_path = public as $$
  select json_build_object(
    'total',     (select count(*) from members),
    'picked',    (select count(*) from members where assigned_number is not null),
    'remaining', 4 - (select count(*) from members where assigned_number is not null))
$$;

-- a member views their OWN result (needs name + code)
create or replace function member_status(p_code text, p_name text) returns json
language plpgsql security definer set search_path = public as $$
declare m members;
begin
  select * into m from members where code_hash = code_hash(p_code);
  if not found or lower(trim(m.name)) <> lower(trim(coalesce(p_name,''))) then
    perform pg_sleep(1);                       -- slows down guessing
    return json_build_object('ok', false, 'error', 'invalid');
  end if;
  return json_build_object('ok', true, 'name', m.name, 'number', m.assigned_number, 'picked_at', m.selected_at);
end $$;

-- the random draw: atomic, server-side, once per member
create or replace function pick_number(p_code text, p_name text) returns json
language plpgsql security definer set search_path = public as $$
declare m members; n int;
begin
  select * into m from members where code_hash = code_hash(p_code);
  if not found or lower(trim(m.name)) <> lower(trim(coalesce(p_name,''))) then
    perform pg_sleep(1);
    return json_build_object('ok', false, 'error', 'invalid');
  end if;

  perform pg_advisory_xact_lock(7001);         -- only one draw runs at a time
  select * into m from members where id = m.id;  -- re-read inside the lock

  if m.assigned_number is not null then        -- already picked: just return the original number
    return json_build_object('ok', true, 'already', true, 'name', m.name, 'number', m.assigned_number);
  end if;

  select g into n from generate_series(1,4) g
  where g not in (select assigned_number from members where assigned_number is not null)
  order by random() limit 1;

  if n is null then
    return json_build_object('ok', false, 'error', 'none_left');
  end if;

  update members set assigned_number = n, selected_at = now(), invite_used = true where id = m.id;
  insert into audit_log (actor, action, detail) values (m.name, 'pick', 'member picked a number');
  return json_build_object('ok', true, 'already', false, 'name', m.name, 'number', n);
end $$;

-- ---------- admin functions (each one checks is_admin()) ----------

create or replace function admin_overview() returns json
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'not authorized'; end if;
  return json_build_object(
    'members', (select coalesce(json_agg(json_build_object('id', id, 'name', name, 'contact', contact,
                  'number', assigned_number, 'selected_at', selected_at, 'invite_used', invite_used)
                  order by created_at), '[]'::json) from members),
    'available', (select coalesce(json_agg(g order by g), '[]'::json) from generate_series(1,4) g
                  where g not in (select assigned_number from members where assigned_number is not null)),
    'audit', (select coalesce(json_agg(a), '[]'::json)
              from (select at, actor, action, detail from audit_log order by id desc limit 25) a));
end $$;

create or replace function admin_add_member(p_name text, p_contact text default null) returns json
language plpgsql security definer set search_path = public as $$
declare c text := new_code(); nid uuid;
begin
  if not is_admin() then raise exception 'not authorized'; end if;
  if (select count(*) from members) >= 4 then return json_build_object('ok', false, 'error', 'full'); end if;
  if length(trim(coalesce(p_name,''))) = 0 then return json_build_object('ok', false, 'error', 'no_name'); end if;
  insert into members (name, contact, code_hash)
    values (trim(p_name), nullif(trim(coalesce(p_contact,'')), ''), code_hash(c)) returning id into nid;
  insert into audit_log (actor, action, detail) values ('admin', 'add_member', trim(p_name));
  return json_build_object('ok', true, 'id', nid, 'code', c);
exception when unique_violation then
  return json_build_object('ok', false, 'error', 'duplicate');
end $$;

create or replace function admin_new_code(p_id uuid) returns json
language plpgsql security definer set search_path = public as $$
declare c text := new_code(); nm text;
begin
  if not is_admin() then raise exception 'not authorized'; end if;
  update members set code_hash = code_hash(c) where id = p_id returning name into nm;
  if nm is null then return json_build_object('ok', false, 'error', 'not_found'); end if;
  insert into audit_log (actor, action, detail) values ('admin', 'new_code', nm);
  return json_build_object('ok', true, 'code', c);
end $$;

create or replace function admin_remove_member(p_id uuid) returns json
language plpgsql security definer set search_path = public as $$
declare nm text;
begin
  if not is_admin() then raise exception 'not authorized'; end if;
  if exists (select 1 from members where id = p_id and assigned_number is not null) then
    return json_build_object('ok', false, 'error', 'has_pick');    -- must reset the draw instead
  end if;
  delete from members where id = p_id returning name into nm;
  insert into audit_log (actor, action, detail) values ('admin', 'remove_member', nm);
  return json_build_object('ok', true);
end $$;

create or replace function admin_reset() returns json
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'not authorized'; end if;
  update members set assigned_number = null, selected_at = null, invite_used = false;
  insert into audit_log (actor, action, detail) values ('admin', 'reset', 'all selections cleared');
  return json_build_object('ok', true);
end $$;

-- ---------- permissions ----------
revoke all on function is_admin(), code_hash(text), new_code(), public_progress(), member_status(text,text),
  pick_number(text,text), admin_overview(), admin_add_member(text,text), admin_new_code(uuid),
  admin_remove_member(uuid), admin_reset() from public;

grant execute on function public_progress(), member_status(text,text), pick_number(text,text) to anon, authenticated;
grant execute on function is_admin(), admin_overview(), admin_add_member(text,text), admin_new_code(uuid),
  admin_remove_member(uuid), admin_reset() to authenticated;

-- =====================================================================
-- AFTER running the above:
-- 1) Supabase > Authentication > Users > Add user (your admin email + password, tick "Auto confirm").
-- 2) Run this once, with YOUR email, to make that user the administrator:
--
--    insert into admins (user_id) select id from auth.users where email = 'you@example.com';
-- =====================================================================
