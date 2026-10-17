-- My Sign update 13: use the new site address https://sign.accessedsolution.com/
-- in notification emails.
-- Run this once in Supabase → SQL Editor (after updates 1–12).

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
        'text', coalesce(p_body, '') || E'\n\nOpen My Sign: https://sign.accessedsolution.com/'
             || E'\n\nYou get this email because email notifications are on in your My Sign profile. You can turn them off there.'
      )
    );
  exception when others then
    raise warning 'My Sign email notification failed: %', sqlerrm;
  end;
end $$;
