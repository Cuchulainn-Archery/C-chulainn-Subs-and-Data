-- =====================================================================
-- STEP 0, PART A — add logins + roles ALONGSIDE the existing anon rules.
-- Safe to run while the live app is in use: nothing here removes or
-- changes any "anon can ..." policy, so the live page keeps working.
-- The new rules apply only to people who are SIGNED IN (role
-- "authenticated"), which only the test branch page does.
-- Run once, in Supabase > SQL Editor. Contains no secrets.
-- =====================================================================

-- ---------- 1. The staff list: which login has which role ----------
create table if not exists public.staff (                 -- one row per login allowed into the app
  user_id   uuid primary key                              -- the login's internal Supabase ID
            references auth.users(id) on delete cascade,  -- deleting the login removes its staff row too
  member_id integer not null,                             -- their CAC member ID (e.g. 5004)
  role      text not null                                 -- what they may do:
            check (role in ('collector','treasurer','workbook'))  -- only these three values allowed
);
alter table public.staff enable row level security;       -- switch on the rules for this table...
-- ...and add NO policies: with rules on and none granted, no phone and no
-- public key can read or change staff. Only you, in the dashboard, can.

-- ---------- 2. Helper: today's date in Ireland ----------
create or replace function public.dublin_today()          -- returns today's date, Irish time
returns date                                              -- a plain date, no time part
language sql stable                                       -- same answer within one request
as $$ select (now() at time zone 'Europe/Dublin')::date $$;  -- server clock converted to Dublin, then cut to a date

-- ---------- 3. Helper: does the signed-in login have one of these roles? ----------
create or replace function public.has_role(variadic wanted text[])  -- e.g. has_role('treasurer') or has_role('collector','treasurer')
returns boolean                                           -- true / false
language sql stable                                       -- same answer within one request
security definer                                          -- runs with owner rights, so it CAN read staff (callers can't)
set search_path = public                                  -- standard safety line for security-definer functions
as $$
  select exists (                                         -- true if at least one row matches
    select 1 from public.staff                            -- look in the staff list
    where user_id = auth.uid()                            -- for the login making this request
      and role = any(wanted)                              -- holding any of the wanted roles
  )
$$;

-- ---------- 4. Helper for the app: who am I, and what role? ----------
create or replace function public.whoami()                -- the app calls this right after sign-in
returns table (role text, member_id integer, display_name text)  -- one row back (or none if not on staff)
language sql stable                                       -- same answer within one request
security definer                                          -- needs to read staff, which callers can't
set search_path = public                                  -- standard safety line
as $$
  select s.role, s.member_id, m.display_name             -- role, ID, and the name from the roster
  from public.staff s                                     -- start from the staff list
  left join public.members m on m.member_id = s.member_id -- add the name (left join: workbook user has no roster name)
  where s.user_id = auth.uid()                            -- only the caller's own row
$$;

-- ---------- 5. Lock the helpers to signed-in users only ----------
revoke execute on function public.has_role(text[]) from public, anon;   -- the public key cannot call it
revoke execute on function public.whoami()          from public, anon;  -- the public key cannot call it
revoke execute on function public.dublin_today()    from public, anon;  -- not sensitive, but no reason to expose it
grant  execute on function public.has_role(text[]) to authenticated;    -- signed-in users can
grant  execute on function public.whoami()          to authenticated;   -- signed-in users can
grant  execute on function public.dublin_today()    to authenticated;   -- signed-in users can

-- ---------- 6. SESSIONS rules for signed-in users ----------
create policy "staff read sessions" on public.sessions    -- who can SEE session rows
  for select to authenticated
  using ( has_role('treasurer')                           -- treasurer sees everything
          or ( has_role('collector')                      -- a collector sees only...
               and session_date = dublin_today()          -- ...today's sessions...
               and transferred is not true ) );           -- ...that haven't been exported

create policy "staff create sessions" on public.sessions  -- who can START a session-day
  for insert to authenticated
  with check ( has_role('treasurer')                      -- treasurer: any date
               or ( has_role('collector')                 -- collector: only...
                    and session_date = dublin_today()     -- ...for today...
                    and transferred is not true ) );      -- ...and not pre-marked as exported

create policy "treasurer updates sessions" on public.sessions  -- marking "transferred"
  for update to authenticated
  using ( has_role('treasurer') )                         -- only the treasurer may change a row...
  with check ( has_role('treasurer') );                   -- ...and the changed row must still pass

create policy "treasurer deletes sessions" on public.sessions  -- "Clear transferred history"
  for delete to authenticated
  using ( has_role('treasurer') );                        -- only the treasurer

-- ---------- 7. ENTRIES rules for signed-in users (still no update, by design) ----------
create policy "staff read entries" on public.entries      -- who can SEE entries
  for select to authenticated
  using ( has_role('treasurer')                           -- treasurer sees everything
          or ( has_role('collector')                      -- a collector sees an entry only if...
               and exists ( select 1 from public.sessions s     -- ...its session...
                            where s.id = entries.session_id     -- (the one this entry belongs to)
                              and s.session_date = dublin_today()  -- ...is today's...
                              and s.transferred is not true ) ) ); -- ...and not yet exported

create policy "staff add entries" on public.entries       -- who can ADD entries
  for insert to authenticated
  with check ( has_role('treasurer')                      -- treasurer: into any session
               or ( has_role('collector')                 -- collector: only into today's open session
                    and exists ( select 1 from public.sessions s
                                 where s.id = entries.session_id
                                   and s.session_date = dublin_today()
                                   and s.transferred is not true ) ) );

create policy "staff remove entries" on public.entries    -- who can DELETE entries ("remove" link)
  for delete to authenticated
  using ( has_role('treasurer')                           -- treasurer: any
          or ( has_role('collector')                      -- collector: only in today's open session
               and exists ( select 1 from public.sessions s
                            where s.id = entries.session_id
                              and s.session_date = dublin_today()
                              and s.transferred is not true ) ) );

-- ---------- 8. MEMBERS rules for signed-in users (still no delete, by design) ----------
create policy "staff read members" on public.members      -- the name list for the member picker
  for select to authenticated
  using ( has_role('collector','treasurer','workbook') ); -- workbook needs it too: an "upsert" checks existing rows

create policy "workbook adds members" on public.members   -- PushMembersToWeb: new member_id
  for insert to authenticated
  with check ( has_role('workbook') );                    -- only the workbook login

create policy "workbook updates members" on public.members  -- PushMembersToWeb: name change
  for update to authenticated
  using ( has_role('workbook') )                          -- only the workbook login may change a row...
  with check ( has_role('workbook') );                    -- ...and the result must still pass
