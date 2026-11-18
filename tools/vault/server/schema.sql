-- Schema for the qsv edge function. Run once in the Supabase SQL editor.
-- Row Level Security stays on with no policies: only the edge function (secret key) can read or write.

create table if not exists cloud_blobs (
  id text primary key check (id ~ '^key-[0-9a-f]{16}$'),
  blob text not null check (length(blob) > 0 and length(blob) <= 65536),
  created_at timestamptz not null default now()
);

alter table cloud_blobs enable row level security;
