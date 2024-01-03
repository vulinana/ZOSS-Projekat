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

![Stablo napada](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/PostgreSQL/Dijagrami/PostreSQL-attack-tree.png)
<br> Stablo napada<br>

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

U nekim slučajevima napadači mogu razmotriti dodavanje dodatnog naloga kako bi sačuvali pristup u slučaju promene lozinke ili onemogućavanja naloga koji se koristi za pristup od strane napadača. Administratori baze podataka možda neće ni primetiti novi nalog ako nije omogućena provera za kreiranje naloga, ili ako nema praćenja i obaveštavanja za ovakvu vrstu aktivnosti. Slika 1.2 prikazuje napadača koji se povezuje sa SQL Serverom i koristi sp_addlogin uskladištenu proceduru putem sqlcmd alata kako bi kreirao novi nalog. Nakon što napadač doda novi nalog na SQL Server, eskalira njegove privilegije pozivanjem sp_addsrvrolemember uskladištene procedure. Ova procedura dodaje novo kreirani nalog u sysadmin fiksnu serversku ulogu, dodeljujući mu isti nivo pristupa kao i podrazumevani sa nalog. <br><br>
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
3. Uklanjanje nepotrebnih uskladištenih procedura [M3]<br>
Ukoliko ne postoji neki specifičan razlog za koji nam trebaju uskladištene procedure, one se mogu u potpunosti ukloniti sa servera. Ukoliko su one ipak u nekim okolnostima neophodne, ali nije potrebno da uvek budu aktivne, treba ih onemogućiti. <br>
Slika 1.3 pruža primer administratora koji se povezuje sa SQL Serverom i pokušava iskoristiti funkcionalnost produžene uskladištene procedure xp_cmdshell. Početna greška ukazuje da je tražena uskladištena procedura onemogućena i da administrator nije u mogućnosti uspešno završiti zahtevanu komandu. <br><br>
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
4. Parametrizovani upiti [M4]<br>
Kada je reč o zloupotrebi uskladištenih procedura u kombinaciji sa SQL injection-om, bitno je koristiti parametrizovane upite u aplikaciji, kako bi se izbeglo direktno umetanje korisničkih podataka u upite. 
U kontekstu Caddie enterprise sistema, sa PostgreSQL-om interaguje NodeJS aplikacija koja koristi Prisma ORM alat za interakciju sa bazama podataka.
Ovaj alat pruža mogućnost korišćenja Prisma Client [[3]](#reference) koji automatski generiše parametrizovane upite, koristeći parametre umesto direktnog umetanja vrednosti u upit. Ovim se efikasno sprečavaju potencijalni SQL injection napadi. 
   ```
    const prisma = new PrismaClient({})
    const result = await prisma.user.findUnique({
      where: {
         email: 'alice@prisma.io',
      },
    })
   ```
    Međutim Prisma Client omogućava i slanje sirovih upita (raw queries) [[4]](#reference) ka bazi podataka, što može biti korisno u određenim situacijama, kao što su zahtevi za izuzetno oprimizovanim upitima ili kada je potrebna podrška za funkcionalnosti koje Prisma Client možda još uvek ne podržava. Upotreba sirovih upita nosi određene rizike pogotovo u vezi sa SQL Injection napadima. Kada se koriste "$queryRaw" i "$executeRaw" metode, unos korisnika se tretira kao parametar u SQL upitu, što znači da će Prisma automatski koristiti prepared statement kako bi se izbeglo dirktno umetanje vrednosti. To pruža određeni nivo zaštite od SQL Injection napada jer se vrednosti tretiraju kao podaci, a ne kao deo samog SQL upita.
   ```
    const userId = "1"
    const novaLozinka = "nova lozinka"
    const result = await prisma.$queryRaw`CALL PromeniLozinku(${userId}, ${novaLozinka})`
    ```
    S druge strane "$queryRawUnsafe" i "$executeRawUnsafe" metode omogućavaju direktno umetanje sirovih podataka koje zadaje korisnik. Ove metode se koriste kada želimo proslediti sirov SQL upit bez ikakve automatske obrade od strane Prisma Client-a što povećava rizik od SQL Injection napada. Kod korišćenja "$queryRawUnsafe" i "$executeRawUnsafe", posebno je bitno paziti da se pravilno upravlja unosima korisnika i da se osigura da su ti unosi bezbedni od zlonamernog SQL koda. Ako se koristi ovaj pristup, preporučuje se temeljna provera i validacija korisničkih unosa pre nego što se unesu u SQL upit kako bi se izbegli potencijalni sigurnosni rizici. Ovaj pristup je nesiguran upravo zbog mogućnosti direktnog umetanja neobrađenih korisničkih podataka u SQL upite, što može dovesti do ranjivosti na SQL injection napade.
    ```
     //Ovaj zlonamerni input bi mogao da dovede do promene lozinke za sve korisnike u sistemu,
      jer uslov OR 1=1 u SQL upitu uvek biva tačan, zanemarujući stvarne vrednosti userId
    
     const userId = "1 OR 1=1; --"
     const novaLozinka = "nova lozinka"
     prisma.$queryRawUnsafe(
         'CALL PromeniLozinku('${userId}', '${novaLozinka}')'
      )
    ```

## Privilege Escalation

Privilege Escalation [[5]](#reference) predstavlja napad s ciljem dobijanja neovlašćenog pristupa povišenim pravima, dozvolama, privilegijama ili ovlašćenjima.
Napadi eskalacije privilegija su podeljeni u dve kategorije: horizontalna eskalacija i vertikalna eskalacija.
Horizontalna eskalacija privilegija podrazumeva situaciju u kojoj napadač pokušava preuzeti kontrolu nad drugim korisničkim nalozima koji imaju slične privilegije kao nalog koji je već kompromitovan.
Obično, ova vrsta eskalacije uključuje naloge nižeg nivoa (na primer, standardnog korisnika) koji možda nemaju odgovarajuću zaštitu. Svaki put kada napadač kompromituje novi nalog, proširuje svoju sferu pristupa sa sličnim privilegijama.
Vertikalna eskalacija privilegija predstavlja povećanje privilegija ili pristupa iznad nivoa koji već poseduje.

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

Konkretan primer zloupotrebe ranjivosti za eskalaciju privilegija - Ranjivost u funkciji sa SECURITY DEFINER [[6]](#reference) <br>
U PostgreSQL, kada se kreira funkcija sa SECURITY DEFINER zastavicom, to znači da će se ta funkcija izvršavati sa privilegijama vlasnika funkcije, a ne sa privilegijama korisnika koji je poziva. Ovo može predstavljati potencijalni bezbednosni rizik ako funkcija nije pravilno zaštićena.
    
     CREATE OR REPLACE FUNCTION public.create_subscription(IN subscription_name text,IN host_ip text,IN portnum text,
                                                             IN password text,IN username text,IN db_name text,IN publisher_name text)    
     RETURNS text 
     LANGUAGE 'plpgsql' 
     VOLATILE SECURITY DEFINER 
     PARALLEL UNSAFE 
     COST 100 
     
    AS $BODY$ 
            DECLARE 
                 persist_dblink_extension boolean; 
            BEGIN 
                persist_dblink_extension := create_dblink_extension(); 
                PERFORM dblink_connect(format('dbname=%s', db_name)); 
                PERFORM dblink_exec(format('CREATE SUBSCRIPTION %s CONNECTION ''host=%s port=%s password=%s user=%s dbname=%s sslmode=require'' PUBLICATION %s',
                                           subscription_name, host_ip, portNum, password, username, db_name, publisher_name)); 
                PERFORM dblink_disconnect(); 
                
U datom kodu, postoji funkcija create_subscription koja ima SECURITY DEFINER zastavicu. Ona se koristi za stvaranje replikacione pretplate unutar PostgreSQL baze podataka. Problem koji se ovde ističe jeste da, ako napadač može kontrolisati parametre koje ta funkcija koristi, kao što su subscription_name, host_ip, portnum, password, username, db_name, i publisher_name, onda bi napadač mogao iskoristiti ovu funkciju za zlonamerne svrhe.

    -- Napadač može ubaciti zlonamerni SQL kod kroz parametre
    CREATE SUBSCRIPTION test3 CONNECTION 'host=127.0.0.1 port=5432 password=malicious_code user=ibm dbname=ibmclouddb sslmode=require' PUBLICATION     
                                          test2_publication WITH (create_slot = false);

Ako malicious_code predstavlja SQL kod sa ciljem eskalacije privilegija, napadač može izazvati izvršenje tog koda unutar konteksta funkcije sa SECURITY DEFINER zastavicom. 

Nakon što napadač uspe u eskalaciji privilegija, posledice mogu biti ozbiljne, jer mu mogu omogućiti neovlašćeni pregled podataka, izmenu ili brisanje podataka, dodavanje lažnih podataka, promene šeme baze podataka, brisanje tabela. 
Na ovaj način napad Privilege Escalation ostvaruje pretnju 'Neovlašćena manipulacija podacima i operacijama' [P1].

### Mitigacije

- Implementacija jakih autentikacionih metoda, poput dvofaktorske autentikacije [M1], zajedno sa pravilno konfigurisanim sigurnosnim postavkama [M2], redovnim ažuriranjem sistema [M5] i redovnom obukom zaposlenih o bezbednosti [M6], predstavljaju ključne preventivne mere protiv Privilege Escalation napada. Redovno ažuriranje sistema smanjuje rizik od eksploatacije poznatih ranjivosti, dok obuke osoblja o bezbednosti podižu svest o potencijalnim pretnjama, uključujući rizik od deljenja akreditacija ili padanja na phishing napade. Ove zajedničke prakse čine organizaciju otpornijom na sajber pretnje, pružajući sveobuhvatan pristup očuvanju bezbednosti informacija.

- Pažljiva upotreba SECURITY DEFINER-a [M9]<br>
Ako se koriste funkcije sa SECURITY DEFINER flagom, bitno je pažljivo razmotriti šta tačno funkcija radi i koji su parametri kontrolisani od strane korisnika. Ako je moguće dobro bi bilo ograničiti privilegije unutar same funkcije. Na primer, ako funkcija vrši SELECT upit, može se ograničiti na minimalni skup tabela koji je potreban za rad funkcije. Takođe dobra praksa je i izbegavanje davanja suvišnih privilegija vlasniku funkcije.


## Ransomware Attack [N3]

Ransomware napad [[7]](#reference) je vrsta cyber napada tokom kog napadač inficira sistem zlonamernim softverom koji šifrira podatke ili blokira pristup korisnicima do određenog vremena,
uz zahtev za plaćanje otkupnine kako bi žrtva ponovo dobila pristup svojim podacima. Iako žrtva plati otkupninu, i dalje postoji mogućnost da nikada ne dobije svoje podatke, pa čak i da budu javno objavljeni.

Napadač prvo pokušava dobiti pristup sistemu koristeći se različitim metodama kao što su brute force napadi, eksploatacija ranjivosti ili phishing. Kada dobije pristup sledi prikupljanje informacija o PostgreSql bazi, tabelama i korisnicima kako bi saznao koji podaci su zanimljivi. <br>
   
    
        SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'; - prikazivanje tabela u bazi podataka
    
        SELECT * FROM ime_tabele; - prikazivanje podataka u tabeli
        
        SELECT usename, usecreatedb, usesuper FROM pg_user; - prikaz korisnika sa njihovim privilegijama
    
    
Nakon prikupljanja podataka, podaci se enkriptuju i na taj način ih čini nečitljivim bez odgovarajućeg ključa za dekripciju. Ovaj proces jednostavno podrazumeva pristupanje podacima, njihovu enkripciju pomoću ključa pod kontrolom napadača i zamenjivanje originalnih podataka enkriptovanim verzijama. Većina varijanti ransomware-a pažljivo bira datoteke koje će enkriptovati kako bi obezbedile stabilnost sistema. Kako bi povećao pritisak na žrtvu, napadač može podatke preneti na lokacije koje on kontroliše i obrisati ih iz sistema. Kako bi ih obrisao prvo je neophodno da se završe backend procesi, tj. procesi koji upravljaju konekcijom klijenta sa bazom podataka. Ovim pokušajem terminacije procesa, napadač želi osloboditi objekte baze podataka kako bi kasnije mogao da ih obriše. To je moguće učiniti sledećom komandom:
   ```
     SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activitz WHERE 
     pg_stat_activity.datname <> 'postgres' AND pid <> pg_backend_pid()
   ```
Ova komanda je deo strategije "Hit and Run" napada, gde napadač nastoji brzo izvršiti svoj plan bez suvišnih mera prikrivanja.
<br><br>
Nakon toga napadač ostavlja poruku, koja sadrži obaveštenje o napadu i zahtev za plaćanje određene sume novca kao što je prikazano na Slici 3.1. Kako bi povećao pritisak, napadač može zapretiti da će javno objaviti ukradene podatke ukoliko otkupnina ne bude plaćena u određenom roku. Na ovaj način Ransomware Attack ostvaruje pretnju 'Gubitak podataka' [P2].

![Slika 3.1](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/PostgreSQL/Slike/ransomware-notes.PNG "Slika 3.1") <br> Slika 3.1<br>

### Mitigacije

1. Jaka autentifikacija [M1] <br>
S obzirom da Ransomware napadi često počinju krađom kredencijala, veoma je bitno koristiti nepredvidive lozinke. Takođe dvofaktorska autentifikacija ili drugi oblici jake autentifikacije znčajno mogu otežati napadačima dobijanje pristupa čak i ko dođe do korisničkih imena i lozinki. <br><br>
2. Sigurnosne konfiguracije [M2] <br>
Bitna stvar je da se pažljivo upravlja privilegijama korisnika i da se broj privilegovanih korisnika smanji na minimum kako bi se ograničio pristup podacima i operacijama. <br><br>
3. Obuka zaposlenih o bezbednosti [M6] <br>
Obuka zaposlenih o bezbednosnim praksama takođe može biti značajan vid prevencije Ransomware napada, pogotovo jer su phishing napadi često njegova početna tačka. <br><br>
4. Redovno pravljenje rezervnih kopija podataka (backup) [M7] <br>
Redovno pravljenje rezerbnih kopija [[8]](#reference) može pomoći brzom oporavku od Ransomware napada. Ako su podaci sigurni na sigurnosnim kopijama, organizacije mogu izbeći plaćanje otkupnine kako bi vratile pristup podacima. Čest je slučaj da žrtve nisu mogle oporaviti svoje podatke sa sigurnosnih kopija, uprkos njihovom pravljenju. Jedan od uzroka za to je kada su podaci sa sigurnosnih kopija stari ili neki deo podataka nedostaje. Međutim ovi podaci takođe mogu biti zaraženi i šifrovani ransomwerom što se najčešće i događa u invazivnim ransomware napadima. Ako se podaci čuvaju na prostoru diska ili deljenog foldera kome se može direktno pristupiti od strane kompromitovanog servera, ransomware će ih takođe zaraziti i šifrovati, čime će onemogućiti oporavak podataka.
Da bi se ovakva šteta sprečila korisno je pravilo "3-2-1". Preporučuje se čuvanje sigurnosnih kopija podataka prema tri pravila: čuvajte tri kopije fajlova, sačuvane na dva različita tipa medija i jednu kopiju čuvajte van radnog mesta (npr fizički odvojeno od ustanove). <br><br>
![Slika 3.2](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/PostgreSQL/Slike/ransomware-321-rule.png "Slika 3.2") <br> Slika 3.2<br>

5. Enkripcija podataka [M8]<br>
Veoma je bitno ekriptovati podatke, tako da čak i ako su podaci ukradeni oni ne cure. Moguće je kriptovati podatke u samoj bazi podataka ili u aplikaciji (NodeJS).

    Ukoliko se kriptovanje vrši na strani PostgreSQL-a [[9]](#reference), može se otežati migracija podataka između različitih baza, ali se smanjuje opterećenje na strani NodeJS aplikacije. Postoji više različitih načina za kriptovanje podataka na strani PostreSQL-a, npr simetrično i asimetrično šifrovanje. Prilikom simetričnog šifrovanja podataka koriste se funkcije za enkriptovanje:
   ```
       pgp_sym_encrypt(data text, psw text [, options text ]) returns bytea
       pgp_sym_encrypt_bytea(data bytea, psw text [, options text ]) returns bytea
   ```
    kao i funkcije za dekriptovanje:
   ```
      pgp_sym_decrypt(msg bytea, psw text [, options text ]) returns text
      pgp_sym_decrypt_bytea(msg bytea, psw text [, options text ]) returns bytea
   ```
    Za asimetrično šifrovanje koriste se funkcije pgp_pub_encrypt, pgp_pub_encrypt_bytea, dok se za dešifrovanje koriste funkcije pgp_pub_decrypt i pgp_pub_decrypt_bytea. 

    Enkripcija na strani NodeJS-a [[10]](#reference) omogućava veću kontrolu (moguće je koristiti različite algoritme enkripcije koji nisu nužno podržani u bazi podataka) i pomaže u održavanju doslednosti u enkripciji između više različitih baza podataka (ukoliko se koristi više različitih baza). Jedan od načina šifrovanja podataka jeste korišćenjem ugrađenje NodeJS biblioteke crypto. Ovu biblioteku je moguće koristiti za šifrovanje podataka bilo kog tipa.
   ```
     //Checking the crypto module
     const crypto = require('crypto');
     const algorithm = 'aes-256-cbc'; //Using AES encryption
     const key = crypto.randomBytes(32);
     const iv = crypto.randomBytes(16);
   
     //Encrypting text
     function encrypt(text) {
         let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
         let encrypted = cipher.update(text);
         encrypted = Buffer.concat([encrypted, cipher.final()]);
         return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
     }

    // Decrypting text
    function decrypt(text) {
        let iv = Buffer.from(text.iv, 'hex');
        let encryptedText = Buffer.from(text.encryptedData, 'hex');
        let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    }
   ```

# Reference 

[1] https://kinsta.com/knowledgebase/what-is-postgresql/ 

[2] https://booksite.elsevier.com/samplechapters/9781597495516/02~Chapter_3.pdf 

[3] https://www.prisma.io/docs/orm/reference/prisma-client-reference 

[4] https://www.prisma.io/docs/orm/prisma-client/queries/raw-database-access/custom-and-type-safe-queries 

[5] https://www.beyondtrust.com/blog/entry/privilege-escalation-attack-defense-explained

[6] https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql

[7] https://www.imperva.com/blog/postgresql-database-ransomware-analysis/ 

[8] https://www.postgresql.fastware.com/postgresql-insider-sec-ransom 

[9] https://www.postgresql.org/docs/current/pgcrypto.html 

[10] https://www.tutorialspoint.com/encrypt-and-decrypt-data-in-nodejs 

