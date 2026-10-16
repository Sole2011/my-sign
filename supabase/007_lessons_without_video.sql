-- My Sign update 7: teachers can post a lesson without a video
-- (for example live online or in-person lessons described in text).
-- Run this once in Supabase → SQL Editor (after updates 1–6).

alter table public.lessons drop constraint lessons_one_video;
alter table public.lessons add constraint lessons_at_most_one_video
  check (video_path is null or youtube_id is null);
