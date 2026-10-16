-- My Sign update 5: YouTube lessons, more phone video formats, and requesting a tutor directly.
-- Run this once in Supabase → SQL Editor (after updates 1–4).
--
-- A lesson now has either an uploaded video or a YouTube link (not both).
-- YouTube links are only allowed for free lessons, because anyone with the
-- link can watch the video; paid lesson videos must be uploaded so they stay
-- locked until the teacher confirms payment.

alter table public.lessons alter column video_path drop not null;

alter table public.lessons
  add column youtube_id text check (youtube_id is null or youtube_id ~ '^[A-Za-z0-9_-]{11}$'),
  add constraint lessons_one_video check ((video_path is null) <> (youtube_id is null)),
  add constraint lessons_youtube_free_only check (youtube_id is null or access = 'free');

update storage.buckets
   set allowed_mime_types = array['video/mp4', 'video/webm', 'video/quicktime', 'video/x-m4v', 'video/3gpp']
 where id = 'lesson-videos';

-- ---------------------------------------------------------------------------
-- Learners can "Connect" with a tutor and ask for a lesson directly, even when
-- the tutor has not posted a lesson yet. Same country rules as before.
-- ---------------------------------------------------------------------------
alter table public.lesson_requests alter column lesson_id drop not null;

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
    learner_email, format, location, preferred_time, message
  ) values (
    null, me.id, teacher.id, me.country, 'Lesson request', me.name, teacher.name,
    (select email from auth.users where id = me.id), p_format, '',
    p_preferred_time, left(coalesce(trim(p_message), ''), 500)
  ) returning id into new_id;
  return new_id;
end $$;

revoke execute on function public.request_tutor(uuid, text, timestamptz, text) from public, anon;
grant execute on function public.request_tutor(uuid, text, timestamptz, text) to authenticated;

