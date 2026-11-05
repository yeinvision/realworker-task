create table if not exists public.member_data (
  user_id uuid primary key references auth.users (id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.member_data enable row level security;

drop policy if exists "Members can read their own data" on public.member_data;
create policy "Members can read their own data"
  on public.member_data for select to authenticated
  using (auth.uid() = user_id);

drop policy if exists "Members can create their own data" on public.member_data;
create policy "Members can create their own data"
  on public.member_data for insert to authenticated
  with check (auth.uid() = user_id);

drop policy if exists "Members can update their own data" on public.member_data;
create policy "Members can update their own data"
  on public.member_data for update to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "Members can delete their own data" on public.member_data;
create policy "Members can delete their own data"
  on public.member_data for delete to authenticated
  using (auth.uid() = user_id);

create table if not exists public.app_admins (
  user_id uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.app_admins enable row level security;

create or replace function public.is_app_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.app_admins
    where user_id = auth.uid()
  );
$$;

revoke all on function public.is_app_admin() from public;
grant execute on function public.is_app_admin() to authenticated;

create table if not exists public.shared_anniversaries (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(trim(name)) between 1 and 120),
  event_type text not null check (event_type in ('생일', '결혼', '출산', '조사', '기타')),
  event_date date not null,
  recurring boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((event_type = '생일') = recurring)
);

alter table public.shared_anniversaries enable row level security;

drop policy if exists "Authenticated members can view shared anniversaries" on public.shared_anniversaries;
create policy "Authenticated members can view shared anniversaries"
  on public.shared_anniversaries for select to authenticated
  using (true);

drop policy if exists "Admins can add shared anniversaries" on public.shared_anniversaries;
drop policy if exists "Authenticated members can add shared anniversaries" on public.shared_anniversaries;
create policy "Authenticated members can add shared anniversaries"
  on public.shared_anniversaries for insert to authenticated
  with check (auth.uid() is not null);

drop policy if exists "Admins can update shared anniversaries" on public.shared_anniversaries;
create policy "Admins can update shared anniversaries"
  on public.shared_anniversaries for update to authenticated
  using (public.is_app_admin())
  with check (public.is_app_admin());

drop policy if exists "Admins can delete shared anniversaries" on public.shared_anniversaries;
create policy "Admins can delete shared anniversaries"
  on public.shared_anniversaries for delete to authenticated
  using (public.is_app_admin());

grant select, insert, update, delete on public.member_data to authenticated;
grant select, insert, update, delete on public.shared_anniversaries to authenticated;

create or replace function public.enforce_realwork_email_domain()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.email is null or lower(split_part(new.email, '@', 2)) <> 'realwork.group' then
    raise exception 'Only @realwork.group accounts are allowed.'
      using errcode = '23514';
  end if;
  return new;
end;
$$;

revoke all on function public.enforce_realwork_email_domain() from public, anon, authenticated;

drop trigger if exists enforce_realwork_email_domain on auth.users;
create trigger enforce_realwork_email_domain
  before insert or update of email on auth.users
  for each row execute function public.enforce_realwork_email_domain();
