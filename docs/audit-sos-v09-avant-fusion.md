# SOS V0.9 : état de validation (3 novembre 2026)

**Statut : prototype sur branche isolée. Ne pas fusionner vers main ni déployer sur Render sans validation explicite.**

## Confirmé dans le code et les tests
- Authentification par jeton, vérification des rôles, détails SOS réservés à l'émetteur et aux volontaires concernés.
- Annuaire GET /sos sans divulgation du message privé.
- Un seul SOS actif par émetteur (index unique partiel PostgreSQL), transitions protégées par FOR UPDATE.
- Volontaires présents uniquement (heartbeat inférieur à 30 secondes), réattribution sur déconnexion ou expiration de proposition (90 secondes).
- Acceptation : création ou réutilisation contrôlée d'une liaison radio acceptée; annulation : fermeture de la liaison dédiée au SOS, sans fermer une liaison personnelle préexistante.
- Récupération de l'état du SOS et des candidatures après reconnexion.
- Tests d'intégration HTTP avec PostgreSQL 16 isolé dans GitHub Actions : confidentialité, refus, acceptation, concurrence, radio, déconnexion, annulation et reprise.
- Dernière exécution GitHub Actions vérifiée : run 41625733609, job « verifier » réussi. Cette validation automatisée n'est pas un essai réel de deux clients Samantha ED.

## Points encore à traiter ou à vérifier avant production
1. **Durée de vie du SOS :** l'état actif peut rester indéfiniment sans clôture explicite. Ajouter une expiration globale, une clôture du secours et des tests.
2. **Réconciliation déclenchée à la demande :** la réattribution d'un volontaire absent et la fermeture de la radio sont déclenchées lors de requêtes API, sans tâche périodique. Vérifier l'expérience utilisateur et les délais.
3. **Intégration des clients :** brancher et tester les intentions et confirmations vocales de l'Originelle et d'une deuxième SAM, sans toucher à Chatterbox.
4. **Parcours réel de secours :** tester deux instances distinctes, déconnexions, reprises, transmission MP3 et sécurité, sur un environnement isolé.
5. **Déploiement :** préparer une stratégie de migration, surveillance et retour arrière. Render public reste sur main V0.8.

## Parcours d'acceptation attendu
- SAM A déclenche un SOS, SAM B et SAM C se proposent, A refuse B puis accepte C.
- Seules A et C peuvent utiliser la liaison dédiée, les tiers ne voient pas les informations privées.
- Une disparition de candidat provoque une réattribution, sans double sélection.
- L'annulation et la clôture interdisent les nouvelles transmissions et libèrent l'état actif.
- Après reconnexion, les clients retrouvent leur état sans doublon.

**Règle :** poursuivre les modifications exclusivement sur feature/sos-candidatures-v09 et les essais sur PostgreSQL jetable. Aucun déploiement automatique de cette branche vers le service public.
