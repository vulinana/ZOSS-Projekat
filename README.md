# Bezbednosna analiza Enterprise sistema Caddie

## Struktura

[AplikativnoResenje](AplikativnoResenje) - implementacija sistema.

[DijagramiArhitektureSistema](DijagramiArhitektureSistema) - sadrži prva tri nivoa C4 dijagrama analiziranog enterprise sistema.
Granice poverljivosti sistema definisane su na dijagramu 2. nivoa.

[EnterpriseSistemCaddie](EnterpriseSistemCaddie/PREGLED_SISTEMA.md) - tekstualan opis sistema.

[ModulIntegracije](ModulIntegracije/) - Modul integracije obuhvata deo sistema namenjen za integracije sa eksternim sistemima i zajedno sa svojim sistemom za upravljanje bazama podataka (MongoDB)

1. [MongoDB](ModulIntegracije/MongoDB) - opis pretnji na MongoDB, napada koji ostvaraju datu pretnju i mitigacija koje sprecavaju napade i umanjuju njihove posledice.
2. [GithubWebhook](ModulIntegracije/GithubWebhook) - opis pretnji pri integraciji sistema sa Github-om, napada koji ostvaruju datu pretnju i mitigacija koje sprečavaju napade i umanjuju njihove posledice.

[ModulPoslovanja](ModulPoslovanja/) - Modul poslovanja obuhvata Core aplikaciju zajedno sa svojim sistemom za upravljanje bazama podataka (PostgreSQL) i eksternim servisima.

1. [AWS-S3](ModulPoslovanja/AWS-S3) - opis pretnji na AWS-S3, napada koji ostvaruju datu pretnju i mitigacija koje sprečavaju napade i umanjuju njihove posledice.
2. [PostgreSQL](ModulPoslovanja/PostgreSQL) - opis pretnji na PostgreSQL, napada koji ostvaruju datu pretnju i mitigacija koje sprečavaju napade i umanjuju njihove posledice.

## Članovi tima

1. Ana Vulin E2 62/2023
2. Sara Sinjeri E2 66/2023
