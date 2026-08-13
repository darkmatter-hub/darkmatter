-- 008_click_attribution.sql
--
-- Records inbound clicks from marketing channels so we can answer "does this
-- channel actually send us anyone?" Until now every tweet linked to a bare
-- darkmatterhub.ai with no tracking, so X traffic was entirely unmeasurable.
--
-- Deliberately stores no IP address and no raw identifiers. Counting clicks
-- per channel per day needs neither, and this product's whole pitch is
-- careful handling of records.

create table if not exists click_events (
  id          bigserial    primary key,
  source      text         not null,           -- 'x', 'hn', 'reddit', ...
  path        text,                            -- landing path after redirect
  user_agent  text,
  referer     text,
  created_at  timestamptz  not null default now()
);

-- Primary query is "clicks per source over a time window".
create index if not exists click_events_source_created_idx
  on click_events (source, created_at desc);

comment on table click_events is
  'Inbound marketing click attribution. Written by GET /go/:source. No PII stored.';
