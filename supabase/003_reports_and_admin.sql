-- My Sign update 3: reporting users, suspensions, and admin tools.
-- Run this once in Supabase → SQL Editor (after schema.sql and 002_direct_payments.sql).
--
-- Members can report other members in their country. Admins see all reports
-- and can suspend members. Suspended members are hidden from everyone else,
-- along with their lessons, and can no longer use the platform.
--
-- To make yourself an admin, run this afterwards with your own email:
--   insert into public.admins (user_id) select id from auth.users where email = 'you@example.com';

-- ---------------------------------------------------------------------------
-- Admins and suspensions
-- ---------------------------------------------------------------------------
alter table public.profiles add column suspended_at timestamptz;

create table public.admins (
  user_id uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.admins enable row level security;

create policy "Admins can see that they are admins" on public.admins
  for select to authenticated using (user_id = auth.uid());

revoke all on public.admins from anon, authenticated;
grant select on public.admins to authenticated;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins where user_id = auth.uid())
$$;

create or replace function public.is_active_member(p_user_id uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = p_user_id and suspended_at is null)
$$;

-- Suspended members get no country, so every country-based rule shuts them out.
create or replace function public.my_country() returns text
language sql stable security definer set search_path = public as $$
  select country from public.profiles where id = auth.uid() and suspended_at is null
$$;

drop policy "Members see people in their own country" on public.profiles;
create policy "Members see themselves and active people in their own country" on public.profiles
  for select to authenticated using (
    id = auth.uid() or (country = public.my_country() and suspended_at is null)
  );

drop policy "Members see lessons in their own country" on public.lessons;
create policy "Members see lessons from active teachers in their own country" on public.lessons
  for select to authenticated using (
    country = public.my_country() and public.is_active_member(owner_id)
  );

-- Same functions as before, now also refusing suspended members.
create or replace function public.request_lesson(
  p_lesson_id uuid, p_format text, p_preferred_time timestamptz, p_message text
) returns uuid
language plpgsql security definer set search_path = public as $$
declare
  me public.profiles%rowtype;
  lesson public.lessons%rowtype;
  new_id uuid;
begin
  select * into me from public.profiles where id = auth.uid();
  if me.id is null or me.suspended_at is not null or me.role <> 'learner' then
    raise exception 'Only active learner accounts can request lessons.';
  end if;
  select * into lesson from public.lessons where id = p_lesson_id;
  if lesson.id is null or lesson.country <> me.country or not public.is_active_member(lesson.owner_id) then
    raise exception 'This tutor is not available in your country.';
  end if;
  if not (p_format = any (lesson.formats)) then
    raise exception 'Choose one of this tutor''s available formats.';
  end if;

  insert into public.lesson_requests (
    lesson_id, learner_id, teacher_id, country, lesson_title, learner_name, teacher_name,
    learner_email, format, location, preferred_time, message
  ) values (
    lesson.id, me.id, lesson.owner_id, me.country, lesson.title, me.name, lesson.creator,
    (select email from auth.users where id = me.id), p_format,
    case when p_format = 'in-person' then lesson.location else '' end,
    p_preferred_time, left(coalesce(trim(p_message), ''), 500)
  ) returning id into new_id;
  return new_id;
end $$;

create or replace function public.respond_to_request(p_request_id uuid, p_decision text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public.my_country() is null then
    raise exception 'Your account is suspended.';
  end if;
  if p_decision not in ('accepted', 'declined') then
    raise exception 'Invalid decision.';
  end if;
  update public.lesson_requests
     set status = p_decision,
         responded_at = now(),
         teacher_email = case when p_decision = 'accepted'
                              then (select email from auth.users where id = auth.uid()) else '' end
   where id = p_request_id and teacher_id = auth.uid() and status = 'pending';
  if not found then
    raise exception 'Request not found or already answered.';
  end if;
end $$;

create or replace function public.confirm_payment(p_request_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public.my_country() is null then
    raise exception 'Your account is suspended.';
  end if;
  update public.lesson_requests
     set paid_at = now()
   where id = p_request_id and teacher_id = auth.uid() and status = 'accepted' and paid_at is null;
  if not found then
    raise exception 'Request not found, not accepted, or already marked as paid.';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- Reports
-- ---------------------------------------------------------------------------
create table public.reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  reported_id uuid not null references public.profiles (id) on delete cascade,
  lesson_id uuid references public.lessons (id) on delete set null,
  reason text not null check (reason in ('harassment', 'inappropriate', 'fraud', 'fake', 'other')),
  details text not null default '' check (char_length(details) <= 1000),
  status text not null default 'open' check (status in ('open', 'reviewed')),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz
);

alter table public.reports enable row level security;

create policy "Members report people in their own country" on public.reports
  for insert to authenticated with check (
    reporter_id = auth.uid()
    and reported_id <> auth.uid()
    and public.my_country() is not null
    and exists (select 1 from public.profiles p where p.id = reported_id and p.country = public.my_country())
  );

revoke all on public.reports from anon, authenticated;
grant insert on public.reports to authenticated;

-- ---------------------------------------------------------------------------
-- Admin tools (each function checks that the caller is an admin)
-- ---------------------------------------------------------------------------
create or replace function public.admin_list_reports() returns table (
  report_id uuid, created_at timestamptz, status text, reason text, details text,
  reporter_name text, reporter_email text,
  reported_id uuid, reported_name text, reported_email text, reported_role text,
  reported_country text, reported_suspended boolean, lesson_title text
)
language sql stable security definer set search_path = public as $$
  select r.id, r.created_at, r.status, r.reason, r.details,
         rp.name, ru.email::text,
         r.reported_id, dp.name, du.email::text, dp.role,
         dp.country, dp.suspended_at is not null, l.title
    from public.reports r
    join public.profiles rp on rp.id = r.reporter_id
    join auth.users ru on ru.id = r.reporter_id
    join public.profiles dp on dp.id = r.reported_id
    join auth.users du on du.id = r.reported_id
    left join public.lessons l on l.id = r.lesson_id
   where public.is_admin()
   order by (r.status = 'open') desc, r.created_at desc
$$;

create or replace function public.admin_review_report(p_report_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    raise exception 'Admins only.';
  end if;
  update public.reports set status = 'reviewed', reviewed_at = now() where id = p_report_id;
end $$;

create or replace function public.admin_set_suspended(p_user_id uuid, p_suspended boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    raise exception 'Admins only.';
  end if;
  if p_user_id = auth.uid() then
    raise exception 'You cannot suspend yourself.';
  end if;
  update public.profiles
     set suspended_at = case when p_suspended then now() else null end
   where id = p_user_id;
end $$;

revoke execute on function public.is_admin(), public.is_active_member(uuid),
  public.admin_list_reports(), public.admin_review_report(uuid), public.admin_set_suspended(uuid, boolean)
  from public, anon;
grant execute on function public.is_admin(), public.is_active_member(uuid),
  public.admin_list_reports(), public.admin_review_report(uuid), public.admin_set_suspended(uuid, boolean)
  to authenticated;
