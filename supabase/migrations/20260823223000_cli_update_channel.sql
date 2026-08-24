alter table public.lookout_update_channels
  drop constraint if exists lookout_update_channels_channel_check;

alter table public.lookout_update_channels
  add constraint lookout_update_channels_channel_check
  check (channel in ('stable', 'cli-stable'));
