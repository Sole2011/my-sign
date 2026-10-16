-- My Sign update 8: suggesting a new lesson time; ratings, recommendations and feedback; asking the admin to remove a review.
-- Run this once in Supabase → SQL Editor (after updates 1–7).
--
-- - The tutor can suggest a new time at any point.
-- - The learner can suggest a new time once the lesson time has passed,
--   or in reply to a time the tutor suggested.
-- - The other person accepts, declines, or suggests another time.
-- Accepting a time on a request that was still pending also accepts the
-- request (and shares contact emails).

alter table public.lesson_requests
  add column proposed_time timestamptz,
  add column proposed_message text not null default '' check (char_length(proposed_message) <= 500),
  add column proposed_by text check (proposed_by in ('learner', 'teacher')),
  add column proposal_status text check (proposal_status in ('pending', 'accepted', 'declined'));

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
    if not (r.preferred_time < now() or (r.proposal_status = 'pending' and r.proposed_by = 'teacher')) then
      raise exception 'You can suggest a new time after the lesson time has passed, or in reply to your tutor.';
    end if;
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

create or replace function public.respond_to_new_time(p_request_id uuid, p_accept boolean) returns void
language plpgsql security definer set search_path = public as $$
declare
  r public.lesson_requests%rowtype;
begin
  if public.my_country() is null then
    raise exception 'Your account is suspended.';
  end if;
  select * into r from public.lesson_requests where id = p_request_id;
  -- Only the other person (not the one who suggested the time) can answer.
  if r.id is null or r.proposal_status is distinct from 'pending' or r.status not in ('pending', 'accepted')
     or not ((r.proposed_by = 'teacher' and r.learner_id = auth.uid())
          or (r.proposed_by = 'learner' and r.teacher_id = auth.uid())) then
    raise exception 'There is no new time waiting for your answer.';
  end if;

  if p_accept then
    update public.lesson_requests
       set preferred_time = r.proposed_time,
           proposal_status = 'accepted',
           status = 'accepted',
           responded_at = coalesce(r.responded_at, now()),
           teacher_email = (select email from auth.users where id = r.teacher_id),
           learner_email = (select email from auth.users where id = r.learner_id)
     where id = p_request_id;
  else
    update public.lesson_requests set proposal_status = 'declined' where id = p_request_id;
  end if;
end $$;

revoke execute on function public.propose_new_time(uuid, timestamptz, text) from public, anon;
revoke execute on function public.respond_to_new_time(uuid, boolean) from public, anon;
grant execute on function public.propose_new_time(uuid, timestamptz, text) to authenticated;
grant execute on function public.respond_to_new_time(uuid, boolean) to authenticated;

-- ---------------------------------------------------------------------------
-- Ratings, recommendations and feedback
-- After an accepted lesson's time has passed, the learner and the tutor can
-- each review the other once per lesson (and edit or delete their review).
-- Reviews are visible to members who can see the reviewed person's profile.
-- ---------------------------------------------------------------------------
create table public.reviews (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references public.lesson_requests (id) on delete cascade,
  reviewer_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  reviewee_id uuid not null references public.profiles (id) on delete cascade,
  rating integer not null check (rating between 1 and 5),
  recommend boolean not null,
  feedback text not null default '' check (char_length(feedback) <= 1000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (request_id, reviewer_id)
);

alter table public.reviews enable row level security;

create policy "Members see reviews of people they can see" on public.reviews
  for select to authenticated using (
    reviewer_id = auth.uid()
    or reviewee_id = auth.uid()
    or exists (select 1 from public.profiles p where p.id = reviewee_id)
  );

create policy "Learner and tutor review each other after a lesson" on public.reviews
  for insert to authenticated with check (
    reviewer_id = auth.uid()
    and public.my_country() is not null
    and exists (
      select 1 from public.lesson_requests r
      where r.id = request_id
        and r.status = 'accepted'
        and r.preferred_time < now()
        and ((r.learner_id = auth.uid() and r.teacher_id = reviewee_id)
          or (r.teacher_id = auth.uid() and r.learner_id = reviewee_id))
    )
  );

create policy "Members edit their own reviews" on public.reviews
  for update to authenticated using (reviewer_id = auth.uid()) with check (reviewer_id = auth.uid());

create policy "Members delete their own reviews" on public.reviews
  for delete to authenticated using (reviewer_id = auth.uid());

revoke all on public.reviews from anon, authenticated;
grant select, insert, delete on public.reviews to authenticated;
grant update (rating, recommend, feedback, updated_at) on public.reviews to authenticated;

-- ---------------------------------------------------------------------------
-- The person who was reviewed can ask the admin to remove a review.
-- These requests arrive in the admin's Reports list.
-- ---------------------------------------------------------------------------
alter table public.reports add column review_id uuid references public.reviews (id) on delete set null;

alter table public.reports drop constraint reports_reason_check;
alter table public.reports add constraint reports_reason_check
  check (reason in ('harassment', 'inappropriate', 'fraud', 'fake', 'irrelevant', 'review_removal', 'other'));

drop policy "Members report lessons, or people they share a lesson request with" on public.reports;
create policy "Members report lessons, people they share a lesson request with, or reviews about them" on public.reports
  for insert to authenticated with check (
    reporter_id = auth.uid()
    and reported_id <> auth.uid()
    and public.my_country() is not null
    and (
      (lesson_id is not null and exists (
        select 1 from public.lessons l where l.id = lesson_id and l.owner_id = reported_id
      ))
      or (review_id is not null and exists (
        select 1 from public.reviews v where v.id = review_id and v.reviewee_id = auth.uid() and v.reviewer_id = reported_id
      ))
      or exists (
        select 1 from public.lesson_requests r
        where (r.learner_id = auth.uid() and r.teacher_id = reported_id)
           or (r.teacher_id = auth.uid() and r.learner_id = reported_id)
      )
    )
  );

-- The admin report list now also returns the review being reported.
drop function public.admin_list_reports();
create function public.admin_list_reports() returns table (
  report_id uuid, created_at timestamptz, status text, reason text, details text,
  reporter_name text, reporter_email text,
  reported_id uuid, reported_name text, reported_email text, reported_role text,
  reported_country text, reported_suspended boolean, lesson_title text,
  review_id uuid, review_rating integer, review_feedback text
)
language sql stable security definer set search_path = public as $$
  select r.id, r.created_at, r.status, r.reason, r.details,
         coalesce(rp.name, 'Deleted account'), coalesce(ru.email::text, ''),
         r.reported_id, coalesce(dp.name, r.reported_name, 'Deleted account'),
         coalesce(du.email::text, r.reported_email, ''), dp.role,
         dp.country, coalesce(dp.suspended_at is not null, false), l.title,
         v.id, v.rating, v.feedback
    from public.reports r
    left join public.profiles rp on rp.id = r.reporter_id
    left join auth.users ru on ru.id = r.reporter_id
    left join public.profiles dp on dp.id = r.reported_id
    left join auth.users du on du.id = r.reported_id
    left join public.lessons l on l.id = r.lesson_id
    left join public.reviews v on v.id = r.review_id
   where public.is_admin()
   order by (r.status = 'open') desc, r.created_at desc
$$;

create or replace function public.admin_delete_review(p_review_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    raise exception 'Admins only.';
  end if;
  update public.reports set status = 'reviewed', reviewed_at = now() where review_id = p_review_id;
  delete from public.reviews where id = p_review_id;
end $$;

revoke execute on function public.admin_list_reports(), public.admin_delete_review(uuid) from public, anon;
grant execute on function public.admin_list_reports(), public.admin_delete_review(uuid) to authenticated;
