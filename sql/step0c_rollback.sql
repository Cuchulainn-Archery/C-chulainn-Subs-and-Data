-- =====================================================================
-- STEP 0 ROLLBACK — puts the original "anon can ..." rules back exactly
-- as they were, if the cutover causes trouble on a collection day.
-- The signed-in rules from part A can stay; they don't get in the way.
-- =====================================================================

create policy "anon can read sessions"   on public.sessions for select to anon using (true);                      -- public read
create policy "anon can insert sessions" on public.sessions for insert to anon with check (true);                 -- public create
create policy "anon can update sessions" on public.sessions for update to anon using (true) with check (true);    -- public update
create policy "anon can delete sessions" on public.sessions for delete to anon using (true);                      -- public delete

create policy "anon can read entries"   on public.entries for select to anon using (true);                        -- public read
create policy "anon can insert entries" on public.entries for insert to anon with check (true);                   -- public add
create policy "anon can delete entries" on public.entries for delete to anon using (true);                        -- public delete

create policy "anon can read members"          on public.members for select to anon using (true);                 -- public read
create policy "anon can add or update members" on public.members for insert to anon with check (true);            -- public add
create policy "anon can update members"        on public.members for update to anon using (true);                 -- public update (original had no with-check)
