-- My Sign update 6: the tutor must accept first, and who can report whom.
-- Run this once in Supabase → SQL Editor (after updates 1–5).

-- Remove the temporary test accounts and test report created while checking the site.
delete from public.reports where reported_name = 'Check Teacher';
delete from auth.users where email like 'mysign-check-%@example.com';

-- ---------------------------------------------------------------------------
-- The tutor must accept first: contact emails are shared only after the tutor
-- accepts a request (both directions).
-- ---------------------------------------------------------------------------
update public.lesson_requests set learner_email = '' where status <> 'accepted';

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
    format, location, preferred_time, message
  ) values (
    lesson.id, me.id, lesson.owner_id, me.country, lesson.title, me.name, lesson.creator,
    p_format, case when p_format = 'in-person' then lesson.location else '' end,
    p_preferred_time, left(coalesce(trim(p_message), ''), 500)
  ) returning id into new_id;
  return new_id;
end $$;

create or replace function public.request_tutor(
  p_teacher_id uuid, p_format text, p_preferred_time timestamptz, p_message text
) returns uuid
language plpgsql security definer set search_path = public as $$
declare
  me public.profiles%rowtype;
  teacher public.profiles%rowtype;
  new_id uuid;
begin
  select * into me from public.profiles where id = auth.uid();
  if me.id is null or me.suspended_at is not null or me.role <> 'learner' then
    raise exception 'Only active learner accounts can request lessons.';
  end if;
  select * into teacher from public.profiles where id = p_teacher_id;
  if teacher.id is null or teacher.role <> 'teacher' or teacher.country <> me.country or teacher.suspended_at is not null then
    raise exception 'This tutor is not available in your country.';
  end if;
  if p_format not in ('virtual', 'in-person') then
    raise exception 'Choose virtual or in person.';
  end if;

  insert into public.lesson_requests (
    lesson_id, learner_id, teacher_id, country, lesson_title, learner_name, teacher_name,
    format, location, preferred_time, message
  ) values (
    null, me.id, teacher.id, me.country, 'Lesson request', me.name, teacher.name,
    p_format, '', p_preferred_time, left(coalesce(trim(p_message), ''), 500)
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
  update public.lesson_requests r
     set status = p_decision,
         responded_at = now(),
         teacher_email = case when p_decision = 'accepted'
                              then (select email from auth.users where id = auth.uid()) else '' end,
         learner_email = case when p_decision = 'accepted'
                              then (select email from auth.users u where u.id = r.learner_id) else '' end
   where r.id = p_request_id and r.teacher_id = auth.uid() and r.status = 'pending';
  if not found then
    raise exception 'Request not found or already answered.';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- Reports: a person can only be reported by a tutor or learner they share a
-- lesson request with. Any member can report a lesson (for example a video
-- that is not a real sign language lesson).
-- ---------------------------------------------------------------------------
alter table public.reports drop constraint reports_reason_check;
alter table public.reports add constraint reports_reason_check
  check (reason in ('harassment', 'inappropriate', 'fraud', 'fake', 'irrelevant', 'other'));

drop policy "Members report people in their own country" on public.reports;
create policy "Members report lessons, or people they share a lesson request with" on public.reports
  for insert to authenticated with check (
    reporter_id = auth.uid()
    and reported_id <> auth.uid()
    and public.my_country() is not null
    and (
      (lesson_id is not null and exists (
        select 1 from public.lessons l where l.id = lesson_id and l.owner_id = reported_id
      ))
      or exists (
        select 1 from public.lesson_requests r
        where (r.learner_id = auth.uid() and r.teacher_id = reported_id)
           or (r.teacher_id = auth.uid() and r.learner_id = reported_id)
      )
    )
  );
