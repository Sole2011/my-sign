-- My Sign update 10: payment proof for direct payments.
-- Run this once in Supabase → SQL Editor (after updates 1–9).
--
-- After paying the tutor directly, the learner sends proof: payment method,
-- transaction number, and optionally a receipt screenshot. The tutor confirms
-- the payment (existing "Mark as paid") or says they did not receive it.
-- Only the learner and the tutor of that request can see the proof.

alter table public.lesson_requests
  add column payment_method text check (payment_method in ('telebirr', 'cbe_birr', 'mpesa', 'bank', 'cash', 'other')),
  add column payment_reference text not null default '' check (char_length(payment_reference) <= 100),
  add column payment_proof_path text check (payment_proof_path is null or char_length(payment_proof_path) <= 200),
  add column payment_submitted_at timestamptz,
  add column payment_rejected_at timestamptz,
  add column payment_reject_note text not null default '' check (char_length(payment_reject_note) <= 300);

-- Learner sends payment proof for an accepted request that is not yet paid.
create or replace function public.submit_payment_proof(
  p_request_id uuid, p_method text, p_reference text, p_proof_path text
) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public.my_country() is null then
    raise exception 'Your account is suspended.';
  end if;
  if p_method not in ('telebirr', 'cbe_birr', 'mpesa', 'bank', 'cash', 'other') then
    raise exception 'Choose how you paid.';
  end if;
  if p_proof_path is not null and p_proof_path not like auth.uid()::text || '/%' then
    raise exception 'Invalid receipt.';
  end if;
  update public.lesson_requests
     set payment_method = p_method,
         payment_reference = left(coalesce(trim(p_reference), ''), 100),
         payment_proof_path = p_proof_path,
         payment_submitted_at = now()
   where id = p_request_id and learner_id = auth.uid() and status = 'accepted' and paid_at is null;
  if not found then
    raise exception 'This lesson is not waiting for payment.';
  end if;
end $$;

-- Tutor says the payment was not received (the learner can send proof again).
create or replace function public.reject_payment_proof(p_request_id uuid, p_note text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public.my_country() is null then
    raise exception 'Your account is suspended.';
  end if;
  update public.lesson_requests
     set payment_rejected_at = now(),
         payment_reject_note = left(coalesce(trim(p_note), ''), 300)
   where id = p_request_id and teacher_id = auth.uid() and paid_at is null and payment_submitted_at is not null;
  if not found then
    raise exception 'There is no payment proof waiting for you.';
  end if;
end $$;

revoke execute on function public.submit_payment_proof(uuid, text, text, text), public.reject_payment_proof(uuid, text) from public, anon;
grant execute on function public.submit_payment_proof(uuid, text, text, text), public.reject_payment_proof(uuid, text) to authenticated;

-- Receipt screenshots: private, visible only to the learner and the tutor.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('payment-proofs', 'payment-proofs', false, 5242880, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do nothing;

create policy "Learners upload their own receipts" on storage.objects
  for insert to authenticated with check (
    bucket_id = 'payment-proofs' and (storage.foldername(name))[1] = auth.uid()::text
  );

create policy "Learner and tutor see a lesson's receipt" on storage.objects
  for select to authenticated using (
    bucket_id = 'payment-proofs'
    and (
      (storage.foldername(name))[1] = auth.uid()::text
      or exists (
        select 1 from public.lesson_requests r
        where r.payment_proof_path = storage.objects.name and r.teacher_id = auth.uid()
      )
    )
  );

create policy "Learners delete their own receipts" on storage.objects
  for delete to authenticated using (
    bucket_id = 'payment-proofs' and (storage.foldername(name))[1] = auth.uid()::text
  );
