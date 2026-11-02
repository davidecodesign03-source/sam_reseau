-- Run only after checking that no sender already has multiple active SOS.
-- This partial unique index is safe for historical cancelled SOS entries.
CREATE UNIQUE INDEX IF NOT EXISTS sam_sos_un_actif_par_emetteur
ON sam_sos (emetteur_id)
WHERE etat IN ('ouvert', 'propose', 'attribue');
