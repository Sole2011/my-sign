-- My Sign update 4: profile pictures and deleting your own account.
-- Run this once in Supabase → SQL Editor (after updates 1–3).

-- ---------------------------------------------------------------------------
-- Profile pictures (private; visible only to members who can see the profile,
-- which means members in the same country)
-- ---------------------------------------------------------------------------
alter table public.profiles add column avatar_path text
  check (avatar_path is null or avatar_path like id::text || '/%');

grant update (avatar_path) on public.profiles to authenticated;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('avatars', 'avatars', false, 2097152, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do nothing;

create policy "Members upload their own profile picture" on storage.objects
  for insert to authenticated with check (
    bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text
  );

create policy "Members see profile pictures of people they can see" on storage.objects
  for select to authenticated using (
    bucket_id = 'avatars'
    and exists (select 1 from public.profiles p where p.avatar_path = storage.objects.name)
  );

create policy "Members delete their own profile picture" on storage.objects
  for delete to authenticated using (
    bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text
  );

-- ---------------------------------------------------------------------------
-- Keep safety reports when a member deletes their account
-- ---------------------------------------------------------------------------
alter table public.reports
  add column reported_name text,
  add column reported_email text;

update public.reports r
   set reported_name = p.name, reported_email = u.email
  from public.profiles p
  join auth.users u on u.id = p.id
 where p.id = r.reported_id;

create or replace function public.snapshot_reported_member() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  select p.name, u.email into new.reported_name, new.reported_email
    from public.profiles p
    join auth.users u on u.id = p.id
   where p.id = new.reported_id;
  return new;
end $$;

create trigger snapshot_reported_member
  before insert on public.reports
  for each row execute function public.snapshot_reported_member();

alter table public.reports
  alter column reporter_id drop not null,
  alter column reported_id drop not null,
  drop constraint reports_reporter_id_fkey,
  drop constraint reports_reported_id_fkey,
  add constraint reports_reporter_id_fkey foreign key (reporter_id) references public.profiles (id) on delete set null,
  add constraint reports_reported_id_fkey foreign key (reported_id) references public.profiles (id) on delete set null;

create or replace function public.admin_list_reports() returns table (
  report_id uuid, created_at timestamptz, status text, reason text, details text,
  reporter_name text, reporter_email text,
  reported_id uuid, reported_name text, reported_email text, reported_role text,
  reported_country text, reported_suspended boolean, lesson_title text
)
language sql stable security definer set search_path = public as $$
  select r.id, r.created_at, r.status, r.reason, r.details,
         coalesce(rp.name, 'Deleted account'), coalesce(ru.email::text, ''),
         r.reported_id, coalesce(dp.name, r.reported_name, 'Deleted account'),
         coalesce(du.email::text, r.reported_email, ''), dp.role,
         dp.country, coalesce(dp.suspended_at is not null, false), l.title
    from public.reports r
    left join public.profiles rp on rp.id = r.reporter_id
    left join auth.users ru on ru.id = r.reporter_id
    left join public.profiles dp on dp.id = r.reported_id
    left join auth.users du on du.id = r.reported_id
    left join public.lessons l on l.id = r.lesson_id
   where public.is_admin()
   order by (r.status = 'open') desc, r.created_at desc
$$;

-- ---------------------------------------------------------------------------
-- Delete my account. Removes the sign-in and, through the existing links,
-- the profile, lessons, requests, saved tutors, and payment details.
-- (The website removes the member's videos and profile picture first.)
-- ---------------------------------------------------------------------------
create or replace function public.delete_my_account() returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then
    raise exception 'Please sign in first.';
  end if;
  delete from auth.users where id = auth.uid();
end $$;

revoke execute on function public.delete_my_account() from public, anon;
grant execute on function public.delete_my_account() to authenticated;
