insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'lookout-release-artifacts',
  'lookout-release-artifacts',
  false,
  536870912,
  array['application/gzip', 'application/zip']
)
on conflict (id) do update set
  public = false,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;
