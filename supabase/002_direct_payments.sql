-- My Sign update 2: direct payments to teachers.
-- Run this once in Supabase → SQL Editor (after schema.sql has already been run).
--
-- Teachers add how learners can pay them (Telebirr, CBE Birr, bank, ...).
-- Only learners with an accepted request from that teacher can see it.
-- Paid lesson videos unlock only after the teacher marks the request as paid.

-- ---------------------------------------------------------------------------
-- Teacher payment details (private; not part of the public profile)
-- ---------------------------------------------------------------------------
create table public.teacher_payment_details (
  teacher_id uuid primary key default auth.uid() references public.profiles (id) on delete cascade,
  details text not null default '' check (char_length(details) <= 300),
  updated_at timestamptz not null default now()
);

alter table public.teacher_payment_details enable row level security;

create policy "Teachers see their payment details" on public.teacher_payment_details
  for select to authenticated using (teacher_id = auth.uid());

create policy "Teachers add their payment details" on public.teacher_payment_details
  for insert to authenticated with check (teacher_id = auth.uid() and public.my_role() = 'teacher');

create policy "Teachers edit their payment details" on public.teacher_payment_details
  for update to authenticated using (teacher_id = auth.uid()) with check (teacher_id = auth.uid());

create policy "Learners see payment details after acceptance" on public.teacher_payment_details
  for select to authenticated using (
    exists (
      select 1 from public.lesson_requests r
      where r.teacher_id = teacher_payment_details.teacher_id
        and r.learner_id = auth.uid()
        and r.status = 'accepted'
    )
  );

revoke all on public.teacher_payment_details from anon;
grant select, insert, update on public.teacher_payment_details to authenticated;

-- ---------------------------------------------------------------------------
-- Teacher confirms that the learner has paid
-- ---------------------------------------------------------------------------
alter table public.lesson_requests add column paid_at timestamptz;

create or replace function public.confirm_payment(p_request_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.lesson_requests
     set paid_at = now()
   where id = p_request_id and teacher_id = auth.uid() and status = 'accepted' and paid_at is null;
  if not found then
    raise exception 'Request not found, not accepted, or already marked as paid.';
  end if;
end $$;

revoke execute on function public.confirm_payment(uuid) from public, anon;
grant execute on function public.confirm_payment(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- Videos: free lessons for everyone in the country; paid lessons only for the
-- teacher and learners whose payment the teacher has confirmed.
-- ---------------------------------------------------------------------------
drop policy "Members watch videos from their own country" on storage.objects;

create policy "Members watch free videos, paid videos after payment" on storage.objects
  for select to authenticated using (
    bucket_id = 'lesson-videos'
    and exists (
      select 1 from public.lessons l
      where l.video_path = storage.objects.name
        and l.country = public.my_country()
        and (
          l.access = 'free'
          or l.owner_id = auth.uid()
          or exists (
            select 1 from public.lesson_requests r
            where r.lesson_id = l.id and r.learner_id = auth.uid() and r.paid_at is not null
          )
        )
    )
  );
