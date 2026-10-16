-- My Sign update 9: the learner and the tutor can both suggest a new lesson
-- date and time at any point; the other person confirms, declines, or
-- suggests another time.
-- Run this once in Supabase → SQL Editor (after updates 1–8).

create or replace function public.propose_new_time(p_request_id uuid, p_time timestamptz, p_message text) returns void
language plpgsql security definer set search_path = public as $$
declare
  r public.lesson_requests%rowtype;
  my_side text;
begin
  if public.my_country() is null then
    raise exception 'Your account is suspended.';
  end if;
  if p_time is null or p_time <= now() then
    raise exception 'Choose a time in the future.';
  end if;
  select * into r from public.lesson_requests where id = p_request_id;
  if r.id is null or r.status not in ('pending', 'accepted') then
    raise exception 'This request cannot be changed.';
  end if;
  if r.teacher_id = auth.uid() then
    my_side := 'teacher';
  elsif r.learner_id = auth.uid() then
    my_side := 'learner';
  else
    raise exception 'This request cannot be changed.';
  end if;

  update public.lesson_requests
     set proposed_time = p_time,
         proposed_message = left(coalesce(trim(p_message), ''), 500),
         proposed_by = my_side,
         proposal_status = 'pending'
   where id = p_request_id;
end $$;
