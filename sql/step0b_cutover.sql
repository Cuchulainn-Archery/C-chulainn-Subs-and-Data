-- =====================================================================
-- STEP 0, PART B — CUTOVER. Removes every "anon can ..." rule, so the
-- public key on its own can no longer read or change anything.
-- Run ONLY when all of these are true:
--   1. The test branch page has passed testing (signed in as collector AND treasurer).
--   2. The branch has been merged, so the live page has the sign-in screen.
--   3. PushMembersToWeb has been changed to sign in as the workbook login, and tested.
-- After this, the OLD page (on any phone that hasn't reloaded) will show load/save errors
-- until it is refreshed. Undo with step0c_rollback.sql.
-- =====================================================================

drop policy if exists "anon can read sessions"   on public.sessions;  -- no more public reading of sessions
drop policy if exists "anon can insert sessions" on public.sessions;  -- no more public creating
drop policy if exists "anon can update sessions" on public.sessions;  -- no more public "mark transferred"
drop policy if exists "anon can delete sessions" on public.sessions;  -- no more public deleting

drop policy if exists "anon can read entries"   on public.entries;    -- no more public reading of names + amounts
drop policy if exists "anon can insert entries" on public.entries;    -- no more public adding
drop policy if exists "anon can delete entries" on public.entries;    -- no more public deleting

drop policy if exists "anon can read members"          on public.members;  -- no more public roster
drop policy if exists "anon can add or update members" on public.members;  -- no more public adding
drop policy if exists "anon can update members"        on public.members;  -- no more public renaming
