# PostgreSQL
PostgreSQL [[1]](#reference), poznat i kao Postgres, predstavlja besplatan sistem za upravljanje relacionim bazama podataka koji pruža efikasno i pouzdano skladište podataka. 
Za PostgreSQL su karakteristične transakcije (sa svojim svojstvima atomičnosti, konzistentnosti, izolacije i izdržljivosti - ACID), automatski ažurirani prikazi, trigeri, strani ključevi i uskladištene procedure.
To je sistem otvorenog koda što znači da korisnici imaju pristup izvornom kodu i mogu da prilagođavaju softver sopstvenim potrebama. 
Poznat je i po svojoj proširivosti jer korisnici imaju mogućnost da kreiraju svoje tipove podataka, funkcije, operatore i jezike. 
Podržava napredne SQL upite, čime omogućava kompleksno modelovanje podataka i efikasno izvršavanje upita, kao i mogućnost replikacije podataka kako bi se povećali dostupnost i skalabilnost. <br>
Kao i svaki drugi softver tako je i PostgreSQL podložan sigurnosnim pretnjama <br>
1. Neovlašćena manipulacija podacima i operacijama [P1]<br>
Ključni resurs ugrožen u okviru PostgreSQL-a su podaci koji se u njemu skladište, kao i operacije nad samom bazom podataka.
Napadač ima mogućnost manipulacije podacima, čime ugrožava njihovu poverljivost, integritet i dostupnost.
Osim toga, može izvršavati opasne operacije nad samom bazom podataka, uključujući brisanje tabela ili promenu strukture podataka, što dodatno kompromituje integritet i operativnost sistema.
Na ovaj način može da nanese štetu pojedincu ili organizaciji sabotažom, špijunažom, da dođe do osetljivih podataka koje bi mogao da zloubotrebi, da vrši ucene ili iznude novca. <br>
2. Gubitak podataka [P2]<br>
U okviru ove pretnje ugroženi su sami podaci u bazi podataka. Deo podataka ili čak svi podaci postaju nedostupni, pa aplikacije koje zavise od njih mogu postati nefunkcionalne.
Napadač podatke čini nedostupnim kako bi vršio iznudu ili ucenu pojedinca/organizacije. Ako bi ukradeni podaci postali javni to može oštetiti reputaciju žrtve.
Klijenti, partneri i korisnici mogu izgubiti poverenje u organizaciju zbog nesposobnosti da zaštiti svoje podatke

![Stablo napada](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/PostgreSQL/Dijagrami/PostgreSql-attack-tree.png)

## Napadi

### Stored Procedure Abuse [N1]

U PostgreSQL-u mogu postojati uskladištene procedure koje su napisane pomoću PostgreSQL proceduralnog jezika zvanog PL/PgSQL.
One često sadrže kompleksne logičke operacije izvršavane u samoj bazi podataka.
Uskladištene procedure omogućavaju ponovnu upotrebu koda (skup naredbi koji se često koriste se može grupisati u proceduru), optimizovati performanse (smanjuje se potreba za slanjem više upita iz aplikacije ka serveru).
Stored Procedure Abuse [[2]](#reference) predstavlja napad koji se fokusira na zloupotrebu tih procedura. 

Prvi korak u ovom napadu jeste dobijanje pristupa nalozima ili aplikacijama koji imaju odgovarajuće dozvole za interakciju sa odgovarajućim procedurama.
Uobičajeni SQL serverski nalog koji je napadaču koristan je unapred izgrađeni administratorski nalog koji se podrazumevano zove System Administrator, ali svakako to može biti i bilo koji drugi koji ima odgovarajuće dozvole.
Jedna od najčešćih metoda za dobijanje pristupa administratorskom nalogu jeste pogađanje lozinke ili napad rečnikom. Administratori prečesto ne uspevaju da konfigurišu naloge sa jakim lozinkama.
Jednom kada napadač ima pristup nalogu koji ima odgovarajuće dozvole za rad sa procedurama on može da ih i iskoristi u svrhu napada. 
Postavlja se pitanje zašto napadači koriste uskladištene procedure za napade ako već imaju pristup nalogu sa visokim nivoom privilegija, kao što je System Administrator.
Poenta napada na stored procedure leži u tome što napadaču omogućava slobodnije kretanje i izvršavanje napada unutar same baze podataka i povezanih aplikacija, 
umesto da se ograniči na osnovne funkcionalnosti koje već ima kao administrator sistema. 
Uskladištene procedure mogu omogućiti napadaču da izvršava SQL upite, manipuliše nad šemama baze podataka i tako izaziva štetne efekte. 
Na ovaj način se ostvaruje pretnja Neovlašćena manipulacija podacima i operacijama [P1].

Jedan od najčešćih scenarija napada jeste korišćenje uskladištenih procedura za dodavanje korisničkih naloga. Slika 1.1 prikazuje napadača koji se povezuje na SQL server koristeći sqlcmd alat i autentifikuje se validnim pristupnim podacima. Nakon uspešne konekcije, napadač koristi xp_cmdshell uskladištenu proceduru da doda novi korisnički nalog na lokalni sistem <br><br>
![Slika 1.1](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/PostgreSQL/Slike/adding-new-account-with-stored-procedure.PNG "Slika 1.1") <br> Slika 1.1<br>

U nekim slučajevima napadači mogu razmotriti dodavanje dodatnog naloga kako bi sačuvali pristup u slučaju promene lozinke ili onemogućavanja naloga koji se koristi za pristup od strane napadača. Adminitratori baze podataka možda neće ni primetiti novi nalog ako nije omogućena provera za kreiranje naloga, ili ako nema praćenja i obaveštavanja za ovakvu vrstu aktivnosti. Slika 1.2 prikazuje napadača koji se povezuje sa SQL Serverom i koristi sp_addlogin uskladištenu proceduru putem sqlcmd alata kako bi kreirao novi nalog. Nakon što napadač doda novi nalog na SQL Server, eskalira njegove privilegije pozivanjem sp_addsrvrolemember uskladištene procedure. Ova procedura dodaje novo kreirani nalog u sysadmin fiksnu serversku ulogu, dodeljujući mu isti nivo pristupa kao i podrazumevani sa nalog. <br><br>
![Slika 1.2](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/PostgreSQL/Slike/new-sa-account.PNG "Slika 1.2") <br> Slika 1.2<br>

Iako prethodni primeri zahtevaju da napadač ima pristup nalogu sa visokim privilegijama, uskladištene procedure se takođe mogu zloupotrebiti u kombinaciji sa SQL Injection-om. Slično kao što je već opisano koristi se procedura xp_cmdshell za dodavanje novog korisnika, medjutim ovog puta napadač izvršava naredbu putem Web forme. <br><br>
    ```
  '; exec master..xp_cmdshell 'net user attacker P@ssw0rd /add'--
    ``` 

#### Mitigacije

1. Jaka autentifikacija [M1]<br>
Slabe lozinke na defaultnim nalozima su jedna od stvari za koje se napadači najčešće hvataju kada pokušavaju da dobiju pristup nalogu i zastrašujuće je koliko puta ovo funkcinoniše čak i u okruženjima koja bi navodno trebala da imaju visoku bezbednost.
Potreba za jakom autentifikacijom je važna bez obzira na tip naloga, ali je duplo važnija kada su u pitanju privilegovani nalozi koji imaju administrativna prava u okviru aplikacije. <br><br>
2. Sigurnosne konfiguracije [M2] <br>
Da bi se postigla dodatna zaštita potrebno je smanjiti površinu dobijanja pristupa nalogu. To se može postići eliminisanjem nepotrebnih resursa kao što su aplikacije koje nisu neophodne za rad SQL servera,
preimenovanjem, onemogućavanjem i/ili brisanjem nepotrebnih naloga. Neophodno je ograničiti privilegije korisničkim nalozima samo na ono što im je potrebno za obavljanje funkcija.<br><br>
3. Uklanjanje nepotrebnih uskladištenih procedura<br>
Ukoliko ne postoji neki specifičan razlog za koji nam trebaju uskladištene procedure, one se mogu u potpunosti ukloniti sa servera. Ukoliko su one ipak u nekim okolnostima neophodne, ali nije potrebno da uvek budu aktivne, treba ih onemogućiti. <br>
Slika 1.3 pruža primer administratora koji se povezuje sa SQL Server-om i pokušava iskoristiti funkcionalnost produžene uskladištene procedure xp_cmdshell. Početna greška ukazuje da je tražena uskladištena procedura onemogućena i da administrator nije u mogućnosti uspešno završiti zahtevanu komandu. <br><br>
   ![Slika 1.3](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/PostgreSQL/Slike/disabled-procedure.PNG "Slika 1.2") <br> Slika 1.3<br>
<br> Međutim, ako uskladištena procedura nije potpuno uklonjena, administrator može ponovo omogućiti proceduru uz nekoliko jednostavnih komandi (pod pretpostavkom da administrator ima odgovarajuće dozvole). Procedura skladišta baze podataka "sp_configure" omogućava konfiguraciju mnogih opcija globalno na SQL Server instanci. Korišćenje "sp_configure" za ponovno omogućavanje uskladištene procedure omogućiće administratoru da nastavi sa zadatkom. <br>
    ```
    -- Omogući napredne opcije
    EXEC sp_configure 'show advanced options', 1
    GO
    -- Primeni promenu konfiguracije
    RECONFIGURE
    GO
    -- Omogući xp_cmdshell
    EXEC sp_configure 'xp_cmdshell', 1
    GO
    -- Primeni promenu konfiguracije
    RECONFIGURE
    GO
    ```
4. Parametrizovani upiti<br>
Kada je reč o zloupotrebi uskladištenih procedura u kombinaciji sa SQL injection-om, bitno je koristiti parametrizovane upite u aplikaciji, kako bi se izbeglo direktno umetanje korisničkih podataka u upite. 
U kontekstu Caddie enterprise sistema, sa PostgreSQL-om interaguje Node.js aplikacija koja koristi Prisma ORM alat za interakciju sa bazama podataka.
Ovaj alat pruža mogućnost korišćenja Prisma Client [[3]](#reference) koji automatski generiše parametrizovane upite, koristeći parametre umesto direktnog umetanja vrednosti u upit. Ovim se efikasno sprečavaju potencijalni SQL injection napadi. 
   ```
    const prisma = new PrismaClient({})
    const result = await prisma.user.findUnique({
      where: {
         email: 'alice@prisma.io',
      },
    })
   ```
    Međutim Prisma Client omogućava i slanje sirovih upita (raw queries) [[4]](#reference) ka bazi podataka, što može biti korisno u određenim situacijama, kao što su zahtevi za izuzetno oprimizovanim upitima ili kada je potrebma podrška za funkcionalnosti koje Prisma Client možda još uvek ne podržava. Upotreba sirovih upita nosi određene rizike pogotovo u vezi sa SQL Injection napadima. Kada se koriste "$queryRaw" i "$executeRaw" metode, unos korisnika se tretira kao parametar u SQL upitu, što znači da će Prisma automatski koristiti prepared statement kako bi se izbeglo dirktno umetanje vrednosti. To pruža određeni nivo zaštite od SQL Injection napada jer se vrednosti tretiraju kao podaci, a ne kao deo samog SQL koda.
   ```
    const email = 'emelie@prisma.io'
    const result = await prisma.$queryRaw`SELECT * FROM User WHERE email = ${email}`
    ```
    S druge strane "$queryRawUnsafe" i "$executeRawUnsafe" metode omogućavaju direktno umetanje sirovih podataka koje zadaje korisnik. Ove metode se koriste kada želimo proslediti sirov SQL upit bez ikakve automatske obrade od strane Prisma Client-a što povećava rizik od SQL Injection napada. Kod korišćenja "$queryRawUnsafe" i "$executeRawUnsafe", posebno je bitno paziti da se pravilno upravlja unosima korisnika i da se osigura da su ti unosi bezbedni od zlonamernih SQL koda. Ako se koristi ovaj pristup, preporučuje se temeljna provera i validacija korisničkih unosa pre nego što se unesu u SQL upit kako bi se izbegli potencijalni sigurnosni rizici. Ovaj pristup je "nesiguran" (unsafe) upravo zbog mogućnosti direktnog umetanja neobrađenih korisničkih podataka u SQL upite, što može dovesti do ranjivosti na SQL injection napade.
    ```
     prisma.$queryRawUnsafe(
     'SELECT * FROM users WHERE email = $1',
     'emelie@prisma.io; DROP TABLE users --'
      )
    ```
6. Evidencija, praćenje i upozoravanje<br>
Zaustavljanje ovih napada je neprestana borba koja se nikad neće završiti, ali najbolji način za ublažavanje uticaja ovih napada je što efikasnije reagovanje.
Ključni element u reagovanju na bilo koji napad je prvo prepoznati da se nešto dešava.

## Privilege Escalation

Privilege Escalation predstavlja napad s ciljem dobijanja neovlašćenog pristupa povišenim pravima, dozvolama, privilegijama ili ovlašćenjima.
Napadi eskalacije privilegija su podeljeni u dve kategorije: horizontalna eskalacija i vertikalna eskalacija.
Horizontalna eskalacija privilegija podrazumeva situaciju u kojoj napadač pokušava preuzeti kontrolu nad drugim korisničkim nalozima koji imaju slične privilegije kao nalog koji je već kompromitovan.
Obično, ova vrsta eskalacije uključuje naloge nižeg nivoa (na primer, standardnog korisnika) koji možda nemaju odgovarajuću zaštitu. Svaki put kada napadač kompromituje novi nalog, proširuje svoju sferu pristupa sa sličnim privilegijama.
Vertikalna eskalacija privilegija povećanje privilegija ili pristupa iznad nivoa koji već poseduje.

Postoji nekoliko različitih načina kako ovaj napad može da se izvrši. <br>
1. Eksploatacija akreditacija <br>
Napad na PostgreSQL putem eksploatacije akreditacija može se sprovoditi krađom ili kompromitovanjem korisničkih imena i lozinki, posebno onih sa visokim privilegijama poput administratora.
Napadač može ciljati slabosti u upravljanju lozinkama, kao što su ponovna upotreba lozinki ili lozinke koje su podložne jednostavnom krađom.
2. Ranjivosti <br>
PostgreSQL može biti meta napada putem iskorišćavanja ranjivosti u softveru, operativnom sistemu ili drugim komponentama. Napadač može iskoristiti ove ranjivosti kako bi dobio neovlašćen pristup, povećao privilegije ili izvršio druge zlonamerne aktivnosti. To može uključivati poznate ranjivosti za koje postoje eksploatacijski kodovi ili alati.
3. Greške u konfiguraciji <br>
Nepropisna konfiguracija PostgreSQL servera može stvoriti prilike za napad na privilegije. To uključuje postavljanje slabih ili podrazumevanih lozinki za privilegovane naloge, nedostatak enkripcije ili loše postavke dozvola. Napadač može iskoristiti takve konfiguracione greške da bi dobio dodatne privilegije.
4. Malware <br>
Malver usmeren na PostgreSQL može se koristiti za krađu akreditacija, praćenje aktivnosti baze podataka ili čak za instalaciju zlonamernog koda koji omogućava dalje eskalacije privilegija. Na primer, malver koji prikuplja informacije o lozinkama ili presreće komunikaciju može biti korišćen za pokretanje napada na privilegije.
5. Social Engineering <br>
Napadač može pokušati izvršiti napad na privilegije putem društvenog inženjeringa, gde pokušava manipulisati korisnicima ili administratorima baze podataka kako bi otkrili akreditacije ili izvršili radnje koje dovode do povećanja privilegija. To može uključivati phishing napade, lažne poruke ili druge oblike manipulacije.

Nakon što napadač uspe u eskalaciji privilegija, posledice mogu biti ozbiljne, jer mu mogu omogućiti neovlašćeni pregled podataka, izmenu ili brisanje podataka, dodavanje lažnih podataka, promene šeme baze podataka, brisanje tabela. 
Na ovaj način napad Privilege Escalation ostvaruje pretnju 'Neovlašćena manipulacija podacima i operacijama' [P1].

### Mitigacije

Mitigacije koje se mogu primeniti kako bi se smanjio rizik od Privilege Escalation napada, a opisane su u prethodnom napadu:
1. Jaka autentifikacija [M1]<br>
2. Sigurnosne konfiguracija [M2] <br>
3. Evidencija, praćenje i upozoravanje [M3] <br><br>

Dodatno:
1. Redovno ažuriranje sistema [M5]<br>
Bitno je pratiti i primenjivati bezbednosne zakrpe i ispravke sistema kako bi se smanjio rizik od eksploatacije poznatih ranjivosti.
Smanjenje šansi da napadač pronađe iskorišćivu ranjivost najbolji je način da se zaustavi svaka vrsta sajber napada. 
<br><br>
2. Obuka zaposlenih o bezbednosti [M6]<br>
Ljudi su obično najslabija karika u sigurnosti svake organizacije.
Oni mogu nesvesno doprineti napadu eskalacije koristeći slabe lozinke, klikćući na zlonamerne linkove ili priloge, i ignorišući upozorenja u vezi sa opasnim veb sajtovima.
Redovne obuke o bezbednosti osiguravaju da se nove pretnje mogu objasniti, kao i da se u svesti zaposlenih održavaju bezbednosne politike.
Potrebno je naglasiti opasnosti i rizike deljenja naloga i akreditacija.

## Ransomware Attack [N3]

Ransomware napad je vrsta cyber napada tokom kog napadač inficira sistem zlonamernim softverom koji šifrira podatke ili blokira pristup korisnicima do određenog vremena,
uz zahtev za plaćanje otkupnine kako bi žrtva ponovo dobila pristup svojim podacima. Iako žrtva plati otkupninu, i dalje postoji mogućnost da nikada ne dobije svoje podatke, pa čak i da budu javno objavljeni.

Napadač prvo pokušava dobiti pristup sistemu koristeći se različitim metodama kao što su brute force napadi, eksploatacija ranjivosti ili phishing. Kada dobije pristup sledi prikupljanje informacija o PostgreSql bazi, tabelama i korisnicima, a zatim enkriptuje podatke i na taj način ih čini nečitljivim bez odgovarajućeg ključa za dekripciju. Kako bi povećao pritisak na žrtvu, napadač može podatke preneti na lokacije koje on kontroliše i obrisati ih iz sistema. Nakon toga ostavlja poruku, koja sadrži obaveštenje o napadu i zahtev za plaćanje određene sume novca. Kako bi povećao pritisak, napadač može zapretiti da će javno objaviti ukradene podatke ukoliko otkupnina ne bude plaćena u određenom roku. Na ovaj način Ransomware Attack ostvaruje pretnju 'Gubitak podataka' [P2].

### Mitigacije

1. Jaka autentifikacija [M1] <br>
S obzirom da Ransomware napadi često počinju krađom kredencijala, veoma je bitno koristiti nepredvidive lozinke. Takođe dvofaktorska autentifikacija ili drugi oblici jake autentifikacije znčajno mogu otežati napadačima dobijanje pristupa čak i ko dođe do korisničkih imena i lozinki. <br><br>
2. Sigurnosne konfiguracije [M2] <br>
Bitna stvar je da se pažljivo upravlja privilegijama korisnika i da se broj privilegovanih korisnika smanji na minimum kako bi se ograničio pristup podacima i operacijama. <br><br>
3. Evidencija praćenje i upozoravanje [M4] <br>
Postavljanjem sistema za detekciju neobičnih događaja može pomoći brzoj identifikaciji sumnjivih događaja <br><br>
4. Redovno ažuriranje sistema [M5] <br>
Neophodno je redovno pratiti i primenjivati redovna ažuriranja sistema, jer nove verzije često ispravljaju ranjivosti i poboljšavaju sigurnost sistema <br><br>
5. Obuka zaposlenih o bezbednosti [M6] <br>
Obuka zaposlenih o bezbednosnim praksama takođe može biti značajan vid prevencije Ransomware napada, pogotovo jer su phishing napadi često njegova početna tačka. <br><br>
7. Redovno pravljenje rezervnih kopija podataka (backup) [M7] <br>
Redovno pravljenje rezerbnih kopija može pomoći brzom oporavku od Ransomware napada. Ukoliko žrtvi nije bitno da li će ovi podaci biti objavljeni, rezervna kopija može u potpunosti da ga spasi.
 
# Reference 

[1] https://kinsta.com/knowledgebase/what-is-postgresql/
[2] https://booksite.elsevier.com/samplechapters/9781597495516/02~Chapter_3.pdf
[3] https://www.prisma.io/docs/orm/reference/prisma-client-reference
[4] https://www.prisma.io/docs/orm/prisma-client/queries/raw-database-access/custom-and-type-safe-queries
[5] https://www.beyondtrust.com/blog/entry/privilege-escalation-attack-defense-explained
[6] https://www.techtarget.com/searchsecurity/tip/6-ways-to-prevent-privilege-escalation-attacks
[7] https://www.imperva.com/blog/postgresql-database-ransomware-analysis/
[8] https://www.postgresql.fastware.com/postgresql-insider-sec-ransom
