-- Allow public-submission documents to remain unlinked until the applicant
-- creates an account and links their application. The upload Edge Function
-- writes document rows with the service role; no anonymous table/storage
-- write policy is added.
alter table public.siwes_documents
  alter column user_id drop not null;

-- Once an applicant links their public application to an account, they can
-- read its private document records through the application ownership link.
drop policy if exists "Applicants or SIWES staff read document records"
  on public.siwes_documents;

create policy "Applicants or SIWES staff read document records"
on public.siwes_documents
for select
to authenticated
using (
  user_id = (select auth.uid())
  or exists (
    select 1
    from public.siwes_applications a
    where a.id = siwes_documents.application_id
      and a.user_id = (select auth.uid())
  )
  or ((auth.jwt() -> 'app_metadata' ->> 'siwes_role') in ('reviewer', 'admin'))
);

-- Public-submission objects are stored under the application UUID. Once
-- linked, only that application's owner or trusted SIWES staff can read them.
drop policy if exists "SIWES owners and trusted staff read private documents"
  on storage.objects;

create policy "SIWES owners and trusted staff read private documents"
on storage.objects
for select
to authenticated
using (
  bucket_id = 'siwes-private'
  and (
    (storage.foldername(name))[1] = (select auth.uid())::text
    or exists (
      select 1
      from public.siwes_documents d
      join public.siwes_applications a on a.id = d.application_id
      where d.storage_path = storage.objects.name
        and a.user_id = (select auth.uid())
    )
    or ((auth.jwt() -> 'app_metadata' ->> 'siwes_role') in ('reviewer', 'admin'))
  )
);
