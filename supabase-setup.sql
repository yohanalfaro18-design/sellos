create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  full_name text not null default '',
  email text,
  role text not null default 'member' check (role in ('member', 'admin')),
  points integer not null default 0 check (points >= 0),
  stamps integer not null default 0 check (stamps between 0 and 10),
  created_at timestamptz not null default now()
);

create unique index if not exists profiles_username_lower_idx
  on public.profiles (lower(username));

create table if not exists public.movements (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  created_by uuid references auth.users(id) on delete set null,
  type text not null check (
    type in ('points_added', 'points_removed', 'stamp_added',
             'stamp_removed', 'card_redeemed')
  ),
  points_delta integer not null default 0,
  stamps_delta integer not null default 0,
  description text not null,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.movements enable row level security;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.profiles
    where id = auth.uid()
      and role = 'admin'
  );
$$;

drop policy if exists "Users can read their own profile or admins can read all"
  on public.profiles;
create policy "Users can read their own profile or admins can read all"
  on public.profiles
  for select
  to authenticated
  using (id = auth.uid() or public.is_admin());

drop policy if exists "Users can read their own movements or admins can read all"
  on public.movements;
create policy "Users can read their own movements or admins can read all"
  on public.movements
  for select
  to authenticated
  using (user_id = auth.uid() or public.is_admin());

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, username, full_name, email, role)
  values (
    new.id,
    coalesce(
      nullif(new.raw_user_meta_data ->> 'username', ''),
      'user_' || left(new.id::text, 8)
    ),
    coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), ''),
    new.email,
    'member'
  )
  on conflict (id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

create or replace function public.add_points(p_user_id uuid, p_amount integer)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or not public.is_admin() then
    raise exception using errcode = '42501', message = 'Se requiere administrador';
  end if;

  if p_amount is null or p_amount <= 0 then
    raise exception 'La cantidad de puntos debe ser mayor que cero';
  end if;

  update public.profiles as p
  set points = p.points + p_amount
  where p.id = p_user_id and p.role = 'member';

  if not found then
    raise exception 'No se encontró el usuario';
  end if;

  insert into public.movements
    (user_id, created_by, type, points_delta, description)
  values
    (p_user_id, auth.uid(), 'points_added', p_amount, 'Puntos sumados');
end;
$$;

create or replace function public.remove_points(p_user_id uuid, p_amount integer)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_points integer;
  removed_points integer;
begin
  if auth.uid() is null or not public.is_admin() then
    raise exception using errcode = '42501', message = 'Se requiere administrador';
  end if;

  if p_amount is null or p_amount <= 0 then
    raise exception 'La cantidad de puntos debe ser mayor que cero';
  end if;

  select p.points
  into current_points
  from public.profiles as p
  where p.id = p_user_id and p.role = 'member'
  for update;

  if not found then
    raise exception 'No se encontró el usuario';
  end if;

  removed_points := least(current_points, p_amount);

  update public.profiles
  set points = points - removed_points
  where id = p_user_id;

  insert into public.movements
    (user_id, created_by, type, points_delta, description)
  values
    (p_user_id, auth.uid(), 'points_removed', -removed_points, 'Puntos descontados');
end;
$$;

create or replace function public.change_stamps(p_user_id uuid, p_delta integer)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or not public.is_admin() then
    raise exception using errcode = '42501', message = 'Se requiere administrador';
  end if;

  if p_delta not in (-1, 1) then
    raise exception 'El cambio debe ser +1 o -1 sello';
  end if;

  update public.profiles as p
  set stamps = p.stamps + p_delta
  where p.id = p_user_id
    and p.role = 'member'
    and p.stamps + p_delta between 0 and 10;

  if not found then
    raise exception 'No se encontró el usuario o el cambio excede el límite de sellos';
  end if;

  insert into public.movements
    (user_id, created_by, type, stamps_delta, description)
  values (
    p_user_id,
    auth.uid(),
    case when p_delta = 1 then 'stamp_added' else 'stamp_removed' end,
    p_delta,
    case when p_delta = 1 then 'Sello agregado' else 'Sello quitado' end
  );
end;
$$;

create or replace function public.redeem_card(p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or not public.is_admin() then
    raise exception using errcode = '42501', message = 'Se requiere administrador';
  end if;

  update public.profiles as p
  set stamps = 0
  where p.id = p_user_id
    and p.role = 'member'
    and p.stamps = 10;

  if not found then
    raise exception 'El usuario no tiene una tarjeta completa para canjear';
  end if;

  insert into public.movements
    (user_id, created_by, type, stamps_delta, description)
  values
    (p_user_id, auth.uid(), 'card_redeemed', -10, 'Tarjeta canjeada por regalo');
end;
$$;

create or replace function public.set_profile_role(p_user_id uuid, p_role text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or not public.is_admin() then
    raise exception using errcode = '42501', message = 'Se requiere administrador';
  end if;

  if p_role not in ('member', 'admin') then
    raise exception 'El tipo de cuenta no es válido';
  end if;

  if p_user_id = auth.uid() then
    raise exception 'No podés cambiar tu propio rol';
  end if;

  update public.profiles
  set role = p_role
  where id = p_user_id;

  if not found then
    raise exception 'No se encontró la cuenta';
  end if;
end;
$$;

revoke all on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

revoke all on function public.add_points(uuid, integer) from public, anon;
grant execute on function public.add_points(uuid, integer) to authenticated;

revoke all on function public.remove_points(uuid, integer) from public, anon;
grant execute on function public.remove_points(uuid, integer) to authenticated;

revoke all on function public.change_stamps(uuid, integer) from public, anon;
grant execute on function public.change_stamps(uuid, integer) to authenticated;

revoke all on function public.redeem_card(uuid) from public, anon;
grant execute on function public.redeem_card(uuid) to authenticated;

revoke all on function public.set_profile_role(uuid, text) from public, anon;
grant execute on function public.set_profile_role(uuid, text) to authenticated;

grant select on public.profiles, public.movements to authenticated;

do $$
declare
  admin_profile_id uuid;
begin
  select id
  into admin_profile_id
  from public.profiles
  where lower(email) = lower('yohan.alfaro.18@gmail.com');

  if admin_profile_id is null then
    raise exception 'No existe un perfil para yohan.alfaro.18@gmail.com. Primero crea esa cuenta en Supabase Authentication → Users y vuelve a ejecutar este bloque.';
  end if;

  update public.profiles
  set role = 'admin'
  where id = admin_profile_id;
end;
$$;
