# Github Webhook App integrisana sa Github API-jem

Github webhook app je aplikacija cija je glavna funkcionalnost integracija sa Github API-jem radi pribavljanja podataka. Podaci koji se prikupljaju komunikacijom sa ovim eksternim servisom jesu podaci o organizacijama, repozitorijumima i svim vrstama contribution-a u tim repozitorijumima. Github webhook-ovi su HTTP callback-ovi koji se koriste kako bi se sistemi integrisani sa Github API-jem obavestili nakon odredjenih dogadjaja (push, pull request, otvaranje issue-a itd).

Neke od postojeci pretnji vezane za sistem integrisan sa GitHub-om:

1. Kradja i manipulacija podacima [P1]

    Kradjom i manipulacijom podataka direktno je narusen princip autenticnosti u CIA trijadi. Bilo da se radi o kradji licnih i osetljivih podataka, koje potom moze da zloupotrebi na razlicite nacine ili o manipulaciji tacnosti podataka, posledica je kompromitovanost sistema.  


2. Nedostupnost sistema [P2]
   
    Dostupnost sistema jedan je od principa CIA trijade koji garantuje da je sistem uvek dostupan korisniku kada mu je potreban. Nivo nedostupnosti sistema koji se tolerise je varijabilan u odnosu na kriticnost sistema. U analiziranom slucaju, replay napad moze direktno da ugrozi dostupnost sistema.

![image](https://github.com/vulinana/ZOSS-Projekat/assets/88163410/8448f0d1-62da-45b6-80df-15cd10156c25)


## Napadi


### 1. Fake Webhook Request Attack [N1]

Fake webhook request attack je napad vezan za sisteme koji vrse integraciju sa GitHub API-jem. Sustina ovog napada bazira se na tome da napadac salje malicionizan HTTP zahtev na webhook endpoint sistema koji se integrise sa Github API-jem. Navedeni napad ima nekoliko koraka:
	
1. Identifikacija mete

    Napadac pokusava da pronadje sistem integrisan sa GitHub-om putem webhook-ova.
     
2. Kreiranje malicioznog zahteva

    Napadac kreira lazan HTTP zahtev koji imitira formatom i strukturom legitiman zahtev koji bi pristigao od Github-a. Ovaj zahtev moze da ukljuci maliciozni payload cija je svrha da eksploatise ranjivosti u sistemu.
	
3. Izvrsavanje malicioznog payload-a

    Kako je slucaj da github potpisuje svoje webhook zahteva, napadac moze pokusati da lazira potpis. U slucaju da sistem nema mehanizam za validaciju i autentifikaciju pristiglog webhook zahteva, sistem ce isprocesirati maliciozni payload. Ovo izvrsavanje moze rezultovati kradjom podataka, izvrsavanjem malicioznog koda ili neplaniranim akcijama. 

#### Mitigacije

1. Validacija payload-a [M1]

    Github potpisuje svoje zahteve sa secret-om koji se cuva u eksternom sistemu. Dakle, Github koristi taj secret kako bi kreirao hash potpis payload-a, koji se salje u X-Hub-Signature header-u. Kada na eksterni sistem pristigne zahtev potrebno je da sistem validira zahtev koristeci taj secret. Sistem preracunava hash payload-a pristiglog zahteva koristeci istu metodu kao i Github (to je uglavnom SHA256). Nakon sto izracuna hash, dovoljno je da ga uporedi sa hash-om koji je pristigao u X-Hub-Signature header-u zahteva. Ukoliko se hash-evi podudaraju moze se zakljuciti da se zahtev zaista poslat od Githuba i preci na obradu istog. Naravno, ukoliko se hash-evi ne podudaraju zahtev ili nije poslat od strane Github-a ili je zahtev u toku transporta menjan, te ce zahtev biti odbijen od strane servera. 

3. Povecanje sigurnost endpointa [M2]

    Ukoliko je moguce, dobra je praksa limitirati ko ima pristup odredjen endpointu, gde bi u ovom slucaju to predstavljao endpoint za Github webhook. Takodje, monitoring neobicnih zahteva bi mogao predstavljati pomoc u identifikovanju laznih zahteva.

4. Redovna rotacija secret-a [M3]

    Periodicna promena secreta sa kojim se payload potpisuje smanjuje rizik da se dogodi koriscenje kompromitovanog secret-a od strane napadaca u laznim zahtevima.

5. Koriscenje WAF-a (Web Application Firewall) [M4]

    Koriscenje WAF-a moze pomoci pri identifikaciji i filterovanju malicioznih napada na osnovu poznatih sablona napada i pruziti dodatan sloj zastite od kompleksnih napada.


### 2. Repository Tampering [N2]

Rizik od repository tampering napada u slucaju servisa integrisanog sa Github-om nije zanemarljiv. Ovaj napad se bazira na neautorizovanim izmenama sadrzaja u repozitorijumima, cije podatke servis dobavlja. Iz razloga sto se webhook-ovi automatski izvrsavaju, sve izmene nacinjene u repositorijumu, zavrsavaju u servisu integrisanom sa Github-om. 

Napad zapocinje od toga da napadac prvo uspeva da neovlasceno pristupi Github repozitorijumu. Neki od nacina na koji napadac moze to da ostvari jesu kompromitovani korisnicki kredencijali, ekploataciju podesavanja u repozitorijumu ili putem socijalnog inzenjeringa. 

U zavisnosti od naloga koji je kompromitovan od strane napadaca razlikuju se dva scenarija:

1. Napadac je kompromitovao nalog koji ima permisije za udaljeno izvrsavanje promena u repozitorijumu, ali nema direktan pristup serveru repozitorijuma ili njegovom fajl sistemu. U ovom slucaju mogucnosti su vise ogranicene, medjutim napadac i dalje ima moc da komituje maliciozan kod ili menja istoriju. Dodatno, ukoliko je CI/CD pipeline podesen, te maliciozne promene mogle bi biti automatski deployovane, a samim tim ubrzo bi zavrsile i u integrisanom sistemu. 

2. U slucaju da je napadac kompromitovao nalog sa vecim permisijama, odnosno dozvolu za pisanje u server repozitorijuma i fajl sistem, on ima vise slobode za maliciozno ponasanje. Napadac je u mogucnosti da menja fajlove repozitorijuma ili konfiguraciju servera, sto dovodi do automatskih promena. Obzirom da ima pristup serveru, potencijalno moze da instalira malware ili pribavlja podatke. Takodje, postoji opcija da sam sebi poveca privilegije obzirom na pristup fajl sistemu. 

Maliciozni kod ubacen prvo u repozitorijum, putem webhook zahteva zavrsava i u sistemu koji se integrisao sa Github-om. Takav kod moze da izvrsi razne operacije u posmatranom sistemu, od kradje podataka, brisanja istih ili dovede do promene ponasanja sistema.

#### Mitigacije

1. Logovanje webhook dogadjaja [M1]

    Na ovaj nacin moguce je ispratiti sve dogadjaje i potencijalno primetiti neocekivane aktivnosti, kao sto su velike promene nad izvornim kodom ili komiti od strane nepoznatih korisnika. 

2. Alert sistem [M2]

    Implementacijom alert sistema integrisani sistem bio bi obavesten u slucaju neobicnih aktivnosti u repozitorijumu koje bi mogle biti posledica repository tampering napada. 

3. Rollback plan [M3]

    Obzirom da se webhook zahtevi izvrsavaju automatski cim se dese dogadjaji koji su interesantni za integrisani sistem, ukoliko se izvrsi repository tampering napad, promene bi se ubrzo nasle i u drugom sistemu. Zato je neophodno postojanje spremnog rollback plana koji ce se izvrsiti cim se uvrdi da je doslo do napada kako bi se sistem vratio u prethodno legitimno stanje (postojanje backup-a je kljucno).


### 3. Replay Tampering [N3]

Replay Tampering u slucaju sistema integrisanog sa GitHub-om putem webhook-ova zasniva se na ponovnom ili odlozenom slanju validnih zahteva. Obzirom da se analizirani sistem oslanja na podatke dobavljene od GitHub za statisticku obradu, ponovljeni zahtevi direktno se odrzavaju na statistiku koja nece prikazivati tacne podatke korisnicima. 

Napadac zapocinje napad presretanjem validnog webhook zahteva koji GitHub salje sistemu. Presretnut zahtev sadrzi citav payload (kao sto su informacije o komitima, push ili pr dogadjajima) zajedno sa svim header-ima, od kojih je glavni X-Hub-Signature header koji sadrzi potpis payload-a neophodan za verifikaciju zahteva. 

Nakon sto je zahtev uspesno presretnut od strane napadaca, on je u stanju da iskoristi taj isti zahtev neogranicen broj puta, sto moze izazvati nezeljeno ponasanje i prikaz netacnih informacija u integrisanom sistemu ukoliko nisu implementirani odgovarajuci mehanizmi zastite protiv navedenog napada. 


#### Mitigacije

1. Implementacija timestamp-a [M1]

    Ukljucivanjem timestamp-a u payload poslatog zahteva, a potom i uvodjenje vremenskog praga koji bi specificirao da zahtevi stariji od navedenog praga nece biti prihvaceni znacajno bi smanjili mogucnost za izvodjenje replay napada.

2. Koriscenje nonce-a [M2]

    Nonce (number used once) predstavlja jedinstveni broj koji se moze slati u payload-u ili posebnom header-u zahteva. Neophodno je da na strani sistema koji je integrisan sa GitHubom postoji baza podataka u kojoj bi se skladistili sve vrednosti nonce-a pristigle u zahtevima. Validacija bi ukljucivala proveru nonce vrednosti pristiglog zahteva sa vrednostima u bazi podataka. Ukoliko se vrednost ne poklapa ni sa jednom postojecom, zakljucuje se da je zahtev validan, u suprotnom moze se pretpostaviti da se radi o ponovljenom zahtevu.

3. HTTPS komunikacija [M3]

    U slucaju koriscenja HTTPS umesto HTTPS sav sadrzaj bio bi enkriptovan, te je presretanje podataka otezano, medjutim ukoliko se ono uspesno obavi, HTTPS ne moze direktno da spreci replay napad.

4. Rate limiting [M4]

    Implementiranjem rate limiting-a na webhook endpoint, ogranicava se broj zahteva koji mogu biti prihvaceni i obradjeni u odredjenom vremenskom intervalu od strane servera. Na ovaj nacin direktno se sistem moze zastiti od DoS napada koji moze biti sproveden putem replay napada.

5. Monitoring [M5]

    Ova mitigacija moze da ukaze na neobicnu aktivnost koji se dogadja u sistemu, kao sto je slanje ponovljenih zahteva u kratkom vremenskom periodu.  

### Reference

1. https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
2. https://blog.korelogic.com/blog/2014/06/26/repository_tampering
3. https://hookdeck.com/webhooks/guides/webhook-security-vulnerabilities-guide
