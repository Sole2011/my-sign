-- My Sign update 12: announcements, dashboard notifications, and email notifications.
-- Run this once in Supabase → SQL Editor (after updates 1–11).
--
-- - Admins post announcements; members see them in their dashboard.
-- - Members get a notification (bell in the dashboard) when something happens
--   in their lesson requests: a new request, accepted/declined, a new time
--   suggested or answered, payment proof sent, payment recorded or not found,
--   and new reviews.
-- - The same notifications are emailed through Resend, unless the member turns
--   email notifications off in their profile. Emails start once the Resend API
--   key is saved (see the last step in the instructions).

-- ---------------------------------------------------------------------------
-- Announcements
-- ---------------------------------------------------------------------------
create table public.announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 100),
  body text not null default '' check (char_length(body) <= 1000),
  audience text not null default 'all' check (audience in ('all', 'teacher', 'learner')),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

alter table public.announcements enable row level security;

create policy "Members see announcements for them" on public.announcements
  for select to authenticated using (
    public.is_admin() or (active and (audience = 'all' or audience = public.my_role()))
  );
create policy "Admins add announcements" on public.announcements
  for insert to authenticated with check (public.is_admin());
create policy "Admins edit announcements" on public.announcements
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "Admins delete announcements" on public.announcements
  for delete to authenticated using (public.is_admin());

revoke all on public.announcements from anon, authenticated;
grant select, insert, update, delete on public.announcements to authenticated;

-- ---------------------------------------------------------------------------
-- Notifications
-- ---------------------------------------------------------------------------
create table public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles (id) on delete cascade,
  title text not null,
  body text not null default '',
  request_id uuid references public.lesson_requests (id) on delete cascade,
  read_at timestamptz,
  created_at timestamptz not null default now()
);

create index notifications_user_created on public.notifications (user_id, created_at desc);

alter table public.notifications enable row level security;

create policy "Members see their notifications" on public.notifications
  for select to authenticated using (user_id = auth.uid());
create policy "Members mark their notifications read" on public.notifications
  for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

revoke all on public.notifications from anon, authenticated;
grant select on public.notifications to authenticated;
grant update (read_at) on public.notifications to authenticated;

alter table public.profiles add column email_notifications boolean not null default true;
grant update (email_notifications) on public.profiles to authenticated;

-- Sends emails from inside the database.
create extension if not exists pg_net with schema extensions;

create or replace function public.notify_member(p_user_id uuid, p_title text, p_body text, p_request_id uuid)
returns void
language plpgsql security definer set search_path = public as $$
declare
  wants_email boolean;
  to_email text;
  api_key text;
begin
  if p_user_id is null then
    return;
  end if;
  insert into public.notifications (user_id, title, body, request_id)
  values (p_user_id, left(p_title, 200), left(coalesce(p_body, ''), 1000), p_request_id);

  -- Email is best effort: a failed email must never stop the lesson action.
  begin
    select p.email_notifications, u.email into wants_email, to_email
      from public.profiles p join auth.users u on u.id = p.id
     where p.id = p_user_id;
    if not coalesce(wants_email, false) or to_email is null then
      return;
    end if;
    select decrypted_secret into api_key from vault.decrypted_secrets where name = 'resend_api_key' limit 1;
    if api_key is null then
      return;
    end if;
    perform net.http_post(
      url := 'https://api.resend.com/emails',
      headers := jsonb_build_object('Authorization', 'Bearer ' || api_key, 'Content-Type', 'application/json'),
      body := jsonb_build_object(
        'from', 'My Sign <no-reply@accessedsolution.com>',
        'to', jsonb_build_array(to_email),
        'subject', p_title,
        'text', coalesce(p_body, '') || E'\n\nOpen My Sign: https://sole2011.github.io/my-sign/'
             || E'\n\nYou get this email because email notifications are on in your My Sign profile. You can turn them off there.'
      )
    );
  exception when others then
    raise warning 'My Sign email notification failed: %', sqlerrm;
  end;
end $$;

-- Lesson times in messages: Ethiopia time for Ethiopia, otherwise UTC.
create or replace function public.lesson_time_label(p_time timestamptz, p_country text) returns text
language sql stable as $$
  select case when p_country = 'ET'
              then to_char(p_time at time zone 'Africa/Addis_Ababa', 'DD Mon YYYY, HH24:MI') || ' (Ethiopia time)'
              else to_char(p_time at time zone 'UTC', 'DD Mon YYYY, HH24:MI') || ' (UTC)' end
$$;

create or replace function public.lesson_request_notifications() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  proposer_name text;
  answerer_id uuid;
  proposer_id uuid;
begin
  if tg_op = 'INSERT' then
    perform public.notify_member(new.teacher_id,
      'New lesson request from ' || new.learner_name,
      new.learner_name || ' wants to connect with you for "' || new.lesson_title || '" on '
        || public.lesson_time_label(new.preferred_time, new.country) || '.'
        || case when new.message <> '' then E'\nMessage: ' || new.message else '' end
        || E'\nOpen My Sign to accept or decline.',
      new.id);
    return new;
  end if;

  if new.status is distinct from old.status and new.status in ('accepted', 'declined') then
    perform public.notify_member(new.learner_id,
      new.teacher_name || case when new.status = 'accepted' then ' accepted' else ' declined' end || ' your lesson request',
      case when new.status = 'accepted'
           then '"' || new.lesson_title || '" on ' || public.lesson_time_label(new.preferred_time, new.country)
                || E'.\nOpen My Sign to see contact details and the video room.'
           else '"' || new.lesson_title || E'" was declined. You can find another tutor on My Sign.' end,
      new.id);
  end if;

  if new.proposal_status = 'pending'
     and (old.proposal_status is distinct from 'pending' or new.proposed_time is distinct from old.proposed_time) then
    proposer_name := case when new.proposed_by = 'teacher' then new.teacher_name else new.learner_name end;
    answerer_id := case when new.proposed_by = 'teacher' then new.learner_id else new.teacher_id end;
    perform public.notify_member(answerer_id,
      proposer_name || ' suggested a new lesson time',
      '"' || new.lesson_title || '": ' || public.lesson_time_label(new.proposed_time, new.country) || '.'
        || case when new.proposed_message <> '' then E'\nMessage: ' || new.proposed_message else '' end
        || E'\nOpen My Sign to accept, decline, or suggest another time.',
      new.id);
  end if;

  if old.proposal_status = 'pending' and new.proposal_status in ('accepted', 'declined') then
    proposer_id := case when new.proposed_by = 'teacher' then new.teacher_id else new.learner_id end;
    perform public.notify_member(proposer_id,
      case when new.proposal_status = 'accepted' then 'Your new lesson time was accepted' else 'Your suggested lesson time was declined' end,
      '"' || new.lesson_title || '": ' || public.lesson_time_label(new.proposed_time, new.country) || '.',
      new.id);
  end if;

  if new.payment_submitted_at is not null and new.payment_submitted_at is distinct from old.payment_submitted_at then
    perform public.notify_member(new.teacher_id,
      new.learner_name || ' says they paid',
      '"' || new.lesson_title || '"' || case when new.payment_reference <> '' then ', transaction ' || new.payment_reference else '' end
        || E'.\nCheck your account, then confirm the payment on My Sign.',
      new.id);
  end if;

  if new.payment_rejected_at is not null and new.payment_rejected_at is distinct from old.payment_rejected_at then
    perform public.notify_member(new.learner_id,
      new.teacher_name || ' could not find your payment',
      '"' || new.lesson_title || '".' || case when new.payment_reject_note <> '' then E'\nNote: ' || new.payment_reject_note else '' end
        || E'\nPlease check and send your proof again on My Sign.',
      new.id);
  end if;

  if new.paid_at is not null and old.paid_at is null then
    perform public.notify_member(new.learner_id,
      new.teacher_name || ' confirmed your payment',
      '"' || new.lesson_title || '" is paid.',
      new.id);
  end if;

  return new;
end $$;

create trigger lesson_request_notifications
  after insert or update on public.lesson_requests
  for each row execute function public.lesson_request_notifications();

create or replace function public.review_notifications() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  perform public.notify_member(new.reviewee_id,
    'You have a new review on My Sign',
    'Someone you had a lesson with rated you ' || repeat('★', new.rating) || repeat('☆', 5 - new.rating) || '.'
      || E'\nOpen My Sign to read it.',
    new.request_id);
  return new;
end $$;

create trigger review_notifications
  after insert on public.reviews
  for each row execute function public.review_notifications();

-- These run only inside the database.
revoke execute on function public.notify_member(uuid, text, text, uuid),
  public.lesson_request_notifications(), public.review_notifications()
  from public, anon, authenticated;
