# MongoDB baza podataka

MongoDB je dokument orijentisana baza podataka poznata po performantnosti, fleksibilnosti i skalabilnosti. Podaci se skladiste u JSON formatu. Svaki podatak predstavlja dokument, dok skup dokumenata cini kolekciju. 
MongoDB je dizajnirana da omoguci skladisnjenje velikog broja podataka i izvrsavanje kompleksnih upita. 

Neke od postojecih pretnji vezanih za MongoDB su sledece:

1. Neovlasceni pristup i manipulacija podacima [P1]
   
    Neovlasceni pristup i manipulacija podacima predstavlja izuzetno visoko rangiranu bezbednosnu pretnju. Ukoliko se ova pretnja ostvari ona moze rezultirati na vise nacina. Neki od njih su kradja osetljivih podataka, novcani gubitak, losa reputacija i pravni problemi. Stoga je kljucno da organizacije obezbede snaznu zastitu i prate najbolje prakse kako bi se rizik od ove pretnje smanjio.

3. Nedostupnost podataka [P2]
   
    Navedena pretnja direktno krsi stavku dostupnosti (Availability) u CIA trijadi. Ova stavka garantuje da su podaci i resursi uvek dostupni autorizovanom korisniku kada god mu zatrebaju. Dostupnost podaka konstantno je ugrozena kako od strane napadaca, tako i od tehnickih problema koji mogu nastati pri odrzavaju sistema. Manjak dostupnosti sistema moze negativno uticati na korisnicko iskustvo, dovodeci do nezadovoljstva pri koriscenju sistema.


![image](https://github.com/vulinana/ZOSS-Projekat/assets/88163410/7a81f573-7c15-4030-b3ba-374e6ff81847)


## Napadi

### IDOR (Insecure Direct Object Reference) [N1]

IDOR napad rezultuje neovlascenim pristupom podacima. Ovaj napad je direktno povezan sa rukovanjem korisnickog unosa pri pristupu podacima u bazi podataka. Generalno gledano, najjednostavniji primer realizacije ovog napada bio bi pristup URL-u 'example.com/profile?user_id=123', gde 123 predstavlja jedinstveni identifikator korisnika na osnovu kog se pribavljaju podaci o istom. Ukoliko ne postoji vid autentifikacije i autorizacije implementirane za proveru prava pristupa korisnika ovim podacima, postoji mogucnost da napadac jednostavnim pogadjanjem pribavi informacije o korisniku za koje nije ovlascen. 

IDOR napad je interesantan u slucaju MongoDB baze podataka iz razloga sto se id objekta u ovoj bazi ne generise u potpunosti nasumicno, samim tim postoji veca sansa da napadac lakse dodje do postojecih identifikatora. Pre svega, potrebno je predstaviti format ObjectID polja koje se generise. ObjectID sastoji se od 12 bajtova, koji su podeljeni u 4 celine u sledecem redosledu:

- Prva 4 bajta predstavljaju sekunde od Unix epohe
- Naredna 3 bajta su identifikator masine
- Sledeca 2 bajta su identifikator procesa
- I na kraju poslednja 3 bajta reprezentuju brojac, koji pocinje od nasumicne vrednosti


Iz navedenog moguce je primetiti da su prve dve celine staticke za objekte koji su kreirani iste sekunde. Takodje, identifikator procesa bi se trebao samo delimicno promeniti ili cak ostati konsistentan od sekunde do sekunde za odredjeni identifikator masine. Na osnovu ovoga, da se zakljuciti da se nasumicnost ObjectID u MongoDB svodi na poslednje poslednju celinu, odnosno poslednja 3 bajta. 

- Postoje dva pristupa na osnovu kojih se moze eksploatisati prethodno navedena cinjenica:

1. Pretpostavljajuci da baza generise vise objekata u jednoj sekundi, imamo nekoliko desetina objekata u pool-u. Nasumicnim generisanjem poslednja 3 bajta ObjectID-a, potreban je samo jedan pogodak kako bi se svi ostali objekti pronasi, jer bi ostali bili kontinuirani i bilo bi potrebno samo inkrementirati ili dekrementirati pogodjen ObjectID.
Sa ovim metodom racunica je da bi bilo potrebno realizovati preko 100000 zahteva u sekundi kreiranja objekta kako bi postojala sansa za pogotkom. 

2. Ova metoda zasniva se na forsiranom kreiranju objekta kako bi postojao pristup validnom ObjectID. Na osnovu tog validnog ObjectID-a, moguce je pristupiti svim objektima eksploatisanjem IDOR-a jednostavnim inkrementiranjem i dekrementiranjem. 

#### Mitigacije

1. Jaka autentifikacija i autorizacija [M1]
   
    Koristiti RBAC (Role based access control) mehanizam da bi se osigiralo da korisnik moze samo da pristupi podacima i vrsi operacije nad istim koje su relevante za njegovu ulogu

2. Indirektne reference objekta [M2]
   
    Umesto koriscenja direktnih referenci u korisnickim interfejsima (u analiziranom slucaju to je ObjectID), ideja je da se koriste indirektne reference. Na primer, umesto koriscenje identifikatora u URL-u, moguce je koristiti drugi skup identifikatora na osnovu kojih je moguce pristupiti podacima, a da oni nemaju bilo kakvu vezu ka ostalim objektima u bazi podataka.

3. Validacija korisnicnog unosa i sanitizacija [M3]

    Implementacija stroge validacije i sanitizacije korisnickog unosa je vazan segment kako bi se osiguralo da je unos u odgovarajucem formatu i ocekivanih vrednosti. 

### MITM (Man in the Middle) [N2]

Man in the Middle napad bazira se na napadacevom presretanju komunikacije izmedju MongoDB servera i klijenta radi prisluskivanja ili izmene informacija. U slucaju neenkriptovane konekcije za komunikaciju sa MongoDB, informacije mogu biti presretnute od strane napadaca. Ovo je poseban rizik ukoliko je baza podataka dostupna preko interneta. Ovaj napad je relevantan za MongoDB iz razloga sto starije verzije MongoDB nisu imale podesen TLS, odnosno enkriptovanu konekciju kao podrazumevano ponasanje, sto je za posledicu imalo veliki broj MongoDB servera sa nedovoljno zasticenom komunikacijom. Takodje, pored cak i omogucene TLS konfiguracije, ukoliko je ona nepravilna ili u slucaju koristenja slabih kriptografskih protokola koje je moguce dekriptovati ostavlja prostor za napadaca da iskoristi ranjivosti sistema. 

Tok napada:

1. Presretanje 

    Napadac zapocinje napad presretanjem mreznog saobracaja. Postoji nekoliko razlicitih tehnika presretanja saobracaja od kojih su neke:
    	- ARP Spoofing - tehnika moguca za izvedbu u slucaju kada je MongoDB hostovan u LAN mrezi. Napada moze iskoristiti ovu tehniku da redirektuje saobracaj od MongoDB servisa do svoje masine, sto im omogucava presretanje, izmenu ili blokiranje upita i odgovara.
    	- DNS Spoofing - tehnika relevantna za MongoDB instance dostupne preko mreze. Ukoliko napada uspe da kompromituje DNS podesavanja, upiti bivaju redirektovani na maliciozni server koji imitira pravu MongoDB instancu, dovodeci do presretanja i korupcije.

2. Dekriptovanje

    Nakon presretanja neophodno je da napadac preuzme kontrolu mreznog saobracaja. Ovo je moguce izvesti koristeci nekoliko tehnika od kojih je za MongoDB relevanta SSL Striping tehnika. 
    	- SSL Stripping - tehnika primenjiva kada konekcije sa MongoDB nisu uopste ili pravilno konfigurisane sa TLS/SSL. Cilj SSL Stripping tehnika jeste snizavanje bezbednosti konekcije sa enkriptovane na neenkriptovanu. 

#### Mitigacije   
1. TLS/SSL enkripcija konekcije [M1]

    Najvaznija mitigacija jeste obezbediti enkriptovane konekcije ka MongoDB kako bi postojala zastita od mogucih tehnika, pogotovo SSL Stripping tehnike. Ova mitigacija ukljucuje koriscenje jakih sifri i savremenih protokola.
	
3. Mere bezbednosti mreze [M2]

    Implementacija snaznih mera bezbednosti mreze predstavlja izuzetno vaznu mitigaciju protiv MitM napada i mogucnih tehnika za njegovu izvedbu. Ova stavka ukljucuje primenu Firewall-a i VPN-a, koji mogu pomoci pri smanjenju rizika od ARP i DNS Spoofing tehnika.
	
5. Monitoring [M3]

    Neizostavna mitigacija koja igra kljucnu ulogu pri detekciji i samim tim odgovoru na potencijalne MitM napade.


### DoS napad [N3]

Denial of Service napad ima za cilj da onemoguci normalno funkcionisanje servera, odnosno da postaje nedostupan svojim korisnicima. Ovaj napad direktno narusava stavku dostupnosti u CIA trijadi. Napadac je u mogucnosti da ovo izvede na nekoliko razlicitih nacina, gde svaki eksploatise razlicit aspekt sistema baze podataka. 

- Tipovi DoS napada na MongoDB

1. Resource Exhaustion 

    Cilj ovog napada je preopterecenje MongoDB servera sa intezivnim operacijama. Napadaci se sluze kompleksnim upitima koji intezivno trose CPU moc, memoriju itd dovodeci do usporenja servera ili pada. Primer ovakvih upita jesu duboko ugnjezdeni agregacioni upiti, gde svaki nivo podupita vrsi operacije kao sto su otpakivanje nizova, vrsenje visestrukih spajanja ili sortiranje velikog broja podataka. 

2. Connection Saturation

    MongoDB ima limitiran broj konkurentnih konekcija koje moze da podrzi. Cilj napadaca jeste da onemoguci server da rukuje sa novim konekcijama na nacin da pokusava da otvori koliko god je moguce novih konekcija ka MongoDB serveru, dostizuci limit. Napadac uspeva da odrzi ove konekcije otvorene saljuci minimalan broj podataka povremeno.  Posledica ovoga jeste da baza prestaje da odgovara redovnim korisnicima jer je maksimalan broj konekcija dostignut, a nijedna se ne oslobadja. 

3. JavaScript Execution

    MongoDB dozvoljava izvrsavanje Javascript izraza ili funkcije za odredjene operacije, od kojih je jedna $where operator. Ukoliko se korisnicki unos ne validira ili ne sanitizuje, moguce je da dodje do injektovanja malicioznog JavaScript koda koji bi u slucaju DoS napada izvrsavao resursno zahtevne operacije, dovodeci do neresponzivnosti servera ili njegovog potpunog pada.


#### Mitigacije

1. Ogranicavanje kompleksnosti upita i uvodjenje timeout-a [M1]

    Uvodjenjem timeouta i ogranicavanjem kompleksnosti upita sprecava se mogucnost iscrpljivanja resursa servera izvrsavanjem kompleksnih upita i dugotrajnih operacija. Ova mitigacija direktno onemogucava Resource Exhaustion tip DoS napada. 

2. Onemogucavanje izvrsavanje Javascript-a [M2]

    Ukoliko za funkcionisanje sistema nije neophodno izvrsavanje JavaScript-a, bitna stavka je onemoguciti izvrsavanje JavaScript-a u MongoDB kako bi se direktno sprecio JavaScript Execution tip DoS napada. 

3. Connection management [M3]

    U navedenu mitigaciju spada monitoring i limitiranje broja konkurentnih konekcija. Implementacija connection poolinga, kao i koriscenje firewall-a za restrikciju pristupa MongoDB serveru mogu otezati Connection Saturation tip DoS napada za napadaca.

4. Redovno azuriranje MongoDB [M4]

    Kako su security patch-evi cesto deo azuriranja, vazno je redovno azurirati verziju MongoDB-a, kako ne bi postojala mogucnost za napadaca da eksploatise ranjivosti koje su vec resene. 

5. Alokacija resursa i monitoring [M5]

    Cilj navedene mitigacije je da se resursi pravilno alociraju (CPU, RAM memorija, prostor na disku) kako bi uspesno obradjivali ocekivan broj zahteva. Pored toga, monitoring pruza dobar uvid u pracenje stanja ovih resursa i omogucava detektovanje znakova iscrpljivanja navedenih resursa. 

### Reference

1. https://data-flair.training/blogs/mitm-attack-types-prevention/?fbclid=IwAR3XWpc4QkTMM1UlLq_pws6W24FHyTgX0SlTovD1oXsiLUOH_LS4R-Xww98
2. https://www.mickaelwalter.fr/idor-with-mongodb-understanding-objectid/?fbclid=IwAR2kWbUp9-cf2SuWvbnhz3eb0dql_UEz-5PZhNnBPGxdaxbeLSTw2OZ47Lo
3. https://infonomics-society.org/wp-content/uploads/ijds/published-papers/volume-8-2017/Security-Vulnerabilities-of-NoSQL-and-SQL-Databases-for-MOOC-Applications.pdf
4. https://owasp.org/www-community/attacks/Denial_of_Service
