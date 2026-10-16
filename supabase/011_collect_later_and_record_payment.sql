-- My Sign update 11: "collect later", recording a payment with its number, and fixing the Supabase function security warning.
-- Run this once in Supabase → SQL Editor (after updates 1–10).
--
-- - A tutor can choose to collect payment later (for example in person, or
--   before they have added payment details).
-- - When the tutor receives the money, they record it: payment method and
--   transaction number are saved with the lesson.

alter table public.lesson_requests add column payment_later boolean not null default false;

create or replace function public.set_payment_later(p_request_id uuid, p_later boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public.my_country() is null then
    raise exception 'Your account is suspended.';
  end if;
  update public.lesson_requests
     set payment_later = coalesce(p_later, false)
   where id = p_request_id and teacher_id = auth.uid() and status = 'accepted' and paid_at is null;
  if not found then
    raise exception 'This lesson is not waiting for payment.';
  end if;
end $$;

-- Tutor records a received payment. Keeps the learner's transaction number
-- unless the tutor types a different one.
create or replace function public.record_payment(p_request_id uuid, p_method text, p_reference text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public.my_country() is null then
    raise exception 'Your account is suspended.';
  end if;
  if p_method is not null and p_method not in ('telebirr', 'cbe_birr', 'mpesa', 'bank', 'cash', 'other') then
    raise exception 'Choose how you were paid.';
  end if;
  update public.lesson_requests
     set paid_at = now(),
         payment_later = false,
         payment_method = coalesce(p_method, payment_method),
         payment_reference = case when coalesce(trim(p_reference), '') <> ''
                                  then left(trim(p_reference), 100) else payment_reference end
   where id = p_request_id and teacher_id = auth.uid() and status = 'accepted' and paid_at is null;
  if not found then
    raise exception 'This lesson is not waiting for payment, or it is already paid.';
  end if;
end $$;

revoke execute on function public.set_payment_later(uuid, boolean), public.record_payment(uuid, text, text) from public, anon;
grant execute on function public.set_payment_later(uuid, boolean), public.record_payment(uuid, text, text) to authenticated;

-- ---------------------------------------------------------------------------
-- Fix the Supabase security warning "Public Can Execute SECURITY DEFINER Function".
-- (Part of update 11.)
--
-- - Visitors who are not signed in can no longer call any My Sign function.
-- - The two functions that only run automatically inside the database
--   (creating a profile at sign-up, saving a reported member's name) can no
--   longer be called by anyone through the website API.
-- - New functions are no longer callable by everyone by default.
-- Signed-in members can still use the functions the website needs; each of
-- those checks who is calling before doing anything.

do $$
declare
  f record;
begin
  for f in
    select p.oid::regprocedure as signature
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.prosecdef
  loop
    execute format('revoke execute on function %s from public, anon', f.signature);
  end loop;
end $$;

revoke execute on function public.handle_new_user() from authenticated;
revoke execute on function public.snapshot_reported_member() from authenticated;

alter default privileges in schema public revoke execute on functions from public, anon;
