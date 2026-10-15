-- My Sign database setup for Supabase.
-- Run this once in Supabase → SQL Editor → New query → Run.
--
-- Rule enforced here (not just in the web page): every member chooses a country
-- when joining, and can only see and connect with tutors and learners in that
-- same country. The country cannot be changed afterwards by the member.

-- ---------------------------------------------------------------------------
-- Profiles (one per signed-up user)
-- ---------------------------------------------------------------------------
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  name text not null check (char_length(name) between 1 and 50),
  role text not null check (role in ('learner', 'teacher')),
  country text not null check (country ~ '^[A-Z]{2}$'),
  city text not null default '' check (char_length(city) <= 60),
  topics text not null default '' check (char_length(topics) <= 120),
  bio text not null default '' check (char_length(bio) <= 500),
  terms_version text not null,
  terms_accepted_at timestamptz not null default now(),
  tax_terms_accepted_at timestamptz,
  created_at timestamptz not null default now()
);

create or replace function public.my_country() returns text
language sql stable security definer set search_path = public as $$
  select country from public.profiles where id = auth.uid()
$$;

create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid()
$$;

-- Create the profile from the sign-up form details. Sign-up fails if the
-- name, role or country is missing or invalid.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  meta jsonb := coalesce(new.raw_user_meta_data, '{}'::jsonb);
begin
  insert into public.profiles (id, name, role, country, terms_version, tax_terms_accepted_at)
  values (
    new.id,
    left(trim(meta ->> 'name'), 50),
    meta ->> 'role',
    upper(meta ->> 'country'),
    coalesce(meta ->> 'terms_version', 'my-sign-draft-1'),
    case when meta ->> 'role' = 'teacher' then now() end
  );
  return new;
end $$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

alter table public.profiles enable row level security;

create policy "Members see people in their own country" on public.profiles
  for select to authenticated using (country = public.my_country());

create policy "Members edit their own profile" on public.profiles
  for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

-- Members may only change these columns (not role or country).
revoke insert, update, delete on public.profiles from anon, authenticated;
grant update (name, city, topics, bio) on public.profiles to authenticated;

-- ---------------------------------------------------------------------------
-- Lessons (published by teachers, visible only in the teacher's country)
-- ---------------------------------------------------------------------------
create table public.lessons (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  country text not null default public.my_country(),
  title text not null check (char_length(title) between 1 and 70),
  description text not null check (char_length(description) between 1 and 200),
  category text not null check (char_length(category) <= 40),
  creator text not null check (char_length(creator) between 1 and 35),
  access text not null check (access in ('free', 'paid')),
  price numeric(12, 2) not null default 0 check (price >= 0 and price <= 100000),
  currency text not null default '' check (char_length(currency) <= 3),
  formats text[] not null check (cardinality(formats) > 0 and formats <@ array['virtual', 'in-person']),
  location text not null default '' check (char_length(location) <= 100),
  video_path text not null,
  created_at timestamptz not null default now()
);

alter table public.lessons enable row level security;

create policy "Members see lessons in their own country" on public.lessons
  for select to authenticated using (country = public.my_country());

create policy "Teachers publish lessons in their own country" on public.lessons
  for insert to authenticated with check (
    owner_id = auth.uid() and country = public.my_country() and public.my_role() = 'teacher'
  );

create policy "Teachers remove their own lessons" on public.lessons
  for delete to authenticated using (owner_id = auth.uid());

revoke update on public.lessons from anon, authenticated;

-- ---------------------------------------------------------------------------
-- Saved tutors (a learner's bookmarks)
-- ---------------------------------------------------------------------------
create table public.saved_tutors (
  learner_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  lesson_id uuid not null references public.lessons (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (learner_id, lesson_id)
);

alter table public.saved_tutors enable row level security;

create policy "Learners see their saved tutors" on public.saved_tutors
  for select to authenticated using (learner_id = auth.uid());

create policy "Learners save tutors in their own country" on public.saved_tutors
  for insert to authenticated with check (
    learner_id = auth.uid()
    and public.my_role() = 'learner'
    and exists (select 1 from public.lessons l where l.id = lesson_id and l.country = public.my_country())
  );

create policy "Learners remove saved tutors" on public.saved_tutors
  for delete to authenticated using (learner_id = auth.uid());

-- ---------------------------------------------------------------------------
-- Lesson requests (learner → tutor, same country only)
-- Created and answered only through the two functions below.
-- ---------------------------------------------------------------------------
create table public.lesson_requests (
  id uuid primary key default gen_random_uuid(),
  lesson_id uuid not null references public.lessons (id) on delete cascade,
  learner_id uuid not null references public.profiles (id) on delete cascade,
  teacher_id uuid not null references public.profiles (id) on delete cascade,
  country text not null,
  lesson_title text not null,
  learner_name text not null,
  teacher_name text not null,
  learner_email text not null default '',
  teacher_email text not null default '',
  format text not null check (format in ('virtual', 'in-person')),
  location text not null default '',
  preferred_time timestamptz not null,
  message text not null default '' check (char_length(message) <= 500),
  status text not null default 'pending' check (status in ('pending', 'accepted', 'declined')),
  created_at timestamptz not null default now(),
  responded_at timestamptz
);

alter table public.lesson_requests enable row level security;

create policy "Learner and tutor see their requests" on public.lesson_requests
  for select to authenticated using (learner_id = auth.uid() or teacher_id = auth.uid());

revoke insert, update, delete on public.lesson_requests from anon, authenticated;

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
  if me.id is null or me.role <> 'learner' then
    raise exception 'Only learner accounts can request lessons.';
  end if;
  select * into lesson from public.lessons where id = p_lesson_id;
  if lesson.id is null or lesson.country <> me.country then
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

-- The tutor's email is shared with the learner only after the tutor accepts.
create or replace function public.respond_to_request(p_request_id uuid, p_decision text) returns void
language plpgsql security definer set search_path = public as $$
begin
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

revoke execute on function public.request_lesson(uuid, text, timestamptz, text) from public, anon;
revoke execute on function public.respond_to_request(uuid, text) from public, anon;
grant execute on function public.request_lesson(uuid, text, timestamptz, text) to authenticated;
grant execute on function public.respond_to_request(uuid, text) to authenticated;

-- ---------------------------------------------------------------------------
-- Lesson videos (private storage; watchable only by members in the same country)
-- ---------------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('lesson-videos', 'lesson-videos', false, 52428800, array['video/mp4', 'video/webm', 'video/quicktime'])
on conflict (id) do nothing;

create policy "Teachers upload videos to their own folder" on storage.objects
  for insert to authenticated with check (
    bucket_id = 'lesson-videos'
    and (storage.foldername(name))[1] = auth.uid()::text
    and public.my_role() = 'teacher'
  );

create policy "Members watch videos from their own country" on storage.objects
  for select to authenticated using (
    bucket_id = 'lesson-videos'
    and exists (
      select 1 from public.lessons l
      where l.video_path = storage.objects.name and l.country = public.my_country()
    )
  );

create policy "Teachers delete their own videos" on storage.objects
  for delete to authenticated using (
    bucket_id = 'lesson-videos' and (storage.foldername(name))[1] = auth.uid()::text
  );

-- ---------------------------------------------------------------------------
-- Access for signed-in members (needed when "Automatically expose new tables"
-- is turned off). Row Level Security above still limits every row by country.
-- ---------------------------------------------------------------------------
grant usage on schema public to authenticated;
revoke all on public.profiles, public.lessons, public.saved_tutors, public.lesson_requests from anon;
grant select on public.profiles to authenticated;
grant select, insert, delete on public.lessons to authenticated;
grant select, insert, delete on public.saved_tutors to authenticated;
grant select on public.lesson_requests to authenticated;
revoke execute on function public.my_country(), public.my_role() from public, anon;
grant execute on function public.my_country(), public.my_role() to authenticated;
