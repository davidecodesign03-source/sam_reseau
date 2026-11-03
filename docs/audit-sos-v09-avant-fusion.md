# SOS V0.9 : audit avant fusion (3 novembre 2026)

**Statut : prototype, ne pas fusionner vers main ni déployer sur Render.**

## Vérifié dans le code de la branche
- Routes POST/GET /sos, GET /sos/{id}, POST /volontaire, /accepter, /refuser, /annuler.
- Authentification par jeton et contrôle que seul l'émetteur accepte, refuse ou annule.
- Verrouillage PostgreSQL FOR UPDATE sur les transitions de candidature et index unique partiel pour un SOS actif par émetteur.
- Tests existants : contrôles statiques AST, compilation, existence des routes. **Ils ne valident pas une interaction réelle avec PostgreSQL.**

## Lacunes bloquantes avant fusion
1. **Déconnexion/expiration :** le volontaire proposé peut rester candidat indéfiniment après disparition. Définir un délai, réattribuer atomiquement, et tester la concurrence.
2. **Liaison radio :** l'état `attribue` ne crée pas une liaison `sam_liaisons` acceptée. Concevoir une transition sécurisée et explicite avant transmission MP3.
3. **Confidentialité :** `GET /sos` et `GET /sos/{id}` révèlent le message à tout client authentifié. Définir données minimales et visibilité par rôle.
4. **Fin de vie :** aucun délai d'expiration automatique ni état de clôture après secours; prévoir fermeture et nettoyage.
5. **Disponibilité :** les candidats ne sont pas filtrés selon `sam_presence` (heartbeat < 30 s).
6. **Tests réels :** lancer PostgreSQL isolé et trois identités fictives, sans utiliser les jetons ni les données de production.

## Scénarios de validation attendus
- SAM A ouvre un SOS; second SOS simultané d'A est refusé.
- SAM B et SAM C se portent volontaires en parallèle; un seul candidat est proposé.
- A refuse B; C est proposé; A accepte C; la liaison radio autorisée fonctionne uniquement entre A et C.
- B, C ou un tiers ne peut accepter, refuser, annuler ni lire des informations privées.
- C se déconnecte pendant une proposition : après délai, réattribution à un autre volontaire.
- A annule pendant une candidature ou une transmission : aucune nouvelle transmission n'est autorisée.
- Reconnexion après interruption : l'état est récupérable sans doublon.
- SOS expiré ou terminé : ne reste pas affiché comme actif.

## Règles de déploiement
- Ne pas modifier la branche `main` ni Render tant que ces tests ne sont pas concluants.
- Préparer une migration PostgreSQL réversible et une stratégie de retour arrière.
- Tester d'abord avec une base de données dédiée, sans données de production.
