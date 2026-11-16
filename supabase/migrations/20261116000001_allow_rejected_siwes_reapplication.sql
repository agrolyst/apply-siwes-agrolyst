-- Allow applicants with rejected applications to reuse their contact details.
-- Active, pending, under-review and approved applications remain unique.
CREATE OR REPLACE FUNCTION public.siwes_contact_duplicate_flags(p_email text DEFAULT NULL::text, p_phone text DEFAULT NULL::text)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  SELECT jsonb_build_object(
    'email_exists',
    CASE
      WHEN nullif(lower(btrim(coalesce(p_email, ''))), '') IS NULL THEN false
      ELSE EXISTS (
        SELECT 1 FROM public.siwes_applications a
        WHERE a.status <> 'rejected'
          AND lower(btrim(coalesce(a.email, ''))) = lower(btrim(p_email))
      )
    END,
    'phone_exists',
    CASE
      WHEN public.siwes_normalize_phone(p_phone) IS NULL THEN false
      ELSE EXISTS (
        SELECT 1 FROM public.siwes_applications a
        WHERE a.status <> 'rejected'
          AND public.siwes_normalize_phone(a.phone) = public.siwes_normalize_phone(p_phone)
      )
    END
  );
$function$;

DROP INDEX IF EXISTS public.siwes_applications_public_email_claim_unique;
CREATE UNIQUE INDEX siwes_applications_public_email_claim_unique
ON public.siwes_applications (lower(btrim(email)))
WHERE public_submission_claim IS TRUE
  AND status <> 'rejected'
  AND NULLIF(btrim(email), '') IS NOT NULL;

DROP INDEX IF EXISTS public.siwes_applications_public_phone_claim_unique;
CREATE UNIQUE INDEX siwes_applications_public_phone_claim_unique
ON public.siwes_applications (public.siwes_normalize_phone(phone))
WHERE public_submission_claim IS TRUE
  AND status <> 'rejected'
  AND NULLIF(btrim(phone), '') IS NOT NULL
  AND public.siwes_normalize_phone(phone) IS NOT NULL;
