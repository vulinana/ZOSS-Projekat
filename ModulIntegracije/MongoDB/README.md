# MongoDB baza podataka

MongoDB je dokument orijentisana baza podataka poznata po performantnosti, fleksibilnosti i skalabilnosti. Podaci se skladište u BSON formatu. Svaki podatak predstavlja dokument, dok skup dokumenata čini kolekciju.
MongoDB je dizajnirana da omogući skladištenje velikog broja podataka i izvršavanje kompleksnih upita.

Neke od postojećih pretnji vezanih za MongoDB su sledeće:

1. Neovlašćeni pristup i manipulacija podacima [P1]

   Neovlašćeni pristup i manipulacija podacima predstavlja izuzetno visoko rangiranu bezbednosnu pretnju. Ukoliko se ova pretnja ostvari ona može rezultirati na više načina. Neki od njih su kradja osetljivih podataka, novčani gubitak, loša reputacija i pravni problemi. Stoga je ključno da organizacije obezbede snažnu zaštitu i prate najbolje prakse kako bi se rizik od ove pretnje smanjio.

2. Nedostupnost podataka [P2]

   Navedena pretnja direktno krši stavku dostupnosti (Availability) u CIA trijadi. Ova stavka garantuje da su podaci i resursi uvek dostupni autorizovanom korisniku kada god mu zatrebaju. Dostupnost podataka konstantno je ugrožena kako od strane napadača, tako i od tehničkih problema koji mogu nastati pri održavanju sistema. Manjak dostupnosti sistema može negativno uticati na korisničko iskustvo, dovodeći do nezadovoljstva pri korišćenju sistema.

![image](https://github.com/vulinana/ZOSS-Projekat/assets/88163410/83429032-61e8-4ad3-9b8d-91fe953e77da)


## Napadi

### IDOR (Insecure Direct Object Reference) [N1]

IDOR napad rezultuje neovlašćenim pristupom podacima. Ovaj napad je direktno povezan sa rukovanjem korisničkog unosa pri pristupu podacima u bazi podataka. Generalno gledano, najjednostavniji primer realizacije ovog napada bio bi pristup URL-u 'example.com/profile?user_id=123', gde 123 predstavlja jedinstveni identifikator korisnika na osnovu kog se pribavljaju podaci o istom. Ukoliko ne postoji vid autentifikacije i autorizacije implementirane za proveru prava pristupa korisnika ovim podacima, postoji mogućnost da napadač jednostavnim pogadjanjem pribavi informacije o korisniku za koje nije ovlašćen.

IDOR napad je interesantan u slučaju MongoDB baze podataka iz razloga sto se id objekta u ovoj bazi ne generiše u potpunosti nasumično, samim tim postoji veća šansa da napadač lakše dodje do postojećih identifikatora. Pre svega, potrebno je predstaviti format ObjectID polja koje se generiše. ObjectID sastoji se od 12 bajtova, koji su podeljeni u 4 celine u sledećem redosledu:

- Prva 4 bajta predstavljaju sekunde od Unix epohe
- Naredna 3 bajta su identifikator mašine
- Sledeća 2 bajta su identifikator procesa
- I na kraju poslednja 3 bajta reprezentuju brojač, koji počinje od nasumične vrednosti

Iz navedenog moguće je primetiti da su prve dve celine statičke za objekte koji su kreirani iste sekunde. Takodje, identifikator procesa bi se trebao samo delimično promeniti ili čak ostati konzistentan od sekunde do sekunde za odredjeni identifikator mašine. Na osnovu ovoga, da se zaključiti da se nasumičnost ObjectID u MongoDB svodi na poslednju celinu, odnosno poslednja 3 bajta.

Važno je naglasiti da je u slučaju analiziranog sistema sam serverski deo aplikacije koja komunicira sa MongoDB bazom podataka implementiran koristeći radni okvir NodeJS. NodeJS je JavaScript radno okruženje namenjeno izvršavanju JavaScript-a na serverskoj strani. Biblioteka koja se koristi u slučaju sistema koji se ovde analizira za komunikaciju aplikacije sa bazom podataka jeste Mongoose. Mongoose je Node.js bazirana Object Data Modeling (ODM) biblioteka. Ona je namenjena za rukovanje vezama izmedju podataka, pružajući mogućnost validacije šema, kao i mapiranje objekata u kodu na objekte u bazi podataka i obrnuto.

Mongoose sam po sebi nema ugradjenu proveru za prava pristupa podacima, već je neophodno kombinacijom mogućnosti koje on nudi sa logikom aplikativnog nivoa implementirati snažnu proveru kontrole pristupa obzirom da je to slaba tačka koju IDOR napad eksploatiše. Sam programer mora biti svestan ove činjenice, te u slučaju korišćenja Mongoose biblioteke u svom sistemu, mora sam implementirati mehanizme kontrole pristupa kako bi zaštitio sistem od ovog napada.

- Postoje dva pristupa na osnovu kojih se moze eksploatisati prethodno navedena cinjenica:

1. Pretpostavljajući da baza generiše više objekata u jednoj sekundi, imamo nekoliko desetina objekata u pool-u. Nasumičnim generisanjem poslednja 3 bajta ObjectID-a, potreban je samo jedan pogodak kako bi se svi ostali objekti pronašli, jer bi ostali bili kontinuirani i bilo bi potrebno samo inkrementirati ili dekrementirati pogodjen ObjectID.
   Sa ovim metodom računica je da bi bilo potrebno realizovati preko 100000 zahteva u sekundi kreiranja objekta kako bi postojala šansa za pogotkom.

2. Ova metoda zasniva se na forsiranom kreiranju objekta kako bi postojao pristup validnom ObjectID. Na osnovu tog validnog ObjectID-a, moguće je pristupiti svim objektima eksploatisanjem IDOR-a jednostavnim inkrementiranjem i dekrementiranjem.

Primer ranjive rute u Node.js koja bi mogla biti eksploatisana od strane napadača predstavljena je u narednom bloku koda:

   ```
   @ApiResponse({ type: [OrganizationMemberPresenter] })
   @Get('/:organizationId/member')
   @ReadOnlyPermission()
   @HttpCode(HttpStatus.OK)
   @UseGuards(
   JwtAuthGuard,
   UserVerifiedGuard,
   PermissionGuard,
   SubscriptionGuard,
   )
   async getOrganizationMembers(
   @Param('organizationId') organizationId: string,
   ) {
   const users = await this.queryBus.execute(
   new GetOrganizationMembersQuery(organizationId),
   );
   return users.map((user) => new OrganizationMemberPopulatedPresenter(user));
   }
   ```

U navedenom primeru moguće je uočiti da ne postoji zaštita i provera prava pristupa korisnika koji bi poslao zahtev na priloženu rutu. Ovo bi napadač mogao lako iskoristiti kao slabost i izvšiti IDOR napad pogodivši identifikator organizacije i na taj način pribaviti podatke za koje nije autorizovan. Iako je u navedenom primeru prikazan read tip IDOR napada, odnosno tip gde napadač vrši napad radi čitanja podataka, važno je napomenuti da postoji i write IDOR, gde je cilj napadača da manipuliše write operacijama nad određenim resursom nad kojim ima neovlašćen pristup. To bi uključivalo rute sa metodama PUT, POST, DELETE itd.

#### Mitigacije

1. Jaka autentifikacija i autorizacija [M1]

   Koristiti RBAC (Role based access control) mehanizam da bi se osigiralo da korisnik može samo da pristupi podacima i vrši operacije nad istim koje su relevante za njegovu ulogu. Način kako bi se prethodni primer koji je podložan IDOR napadu mogao unaprediti da napadač ne može da pristupi u ovom slučaju podacima o članovima organizacije bila bi implementacija dodatnog guard-a koji bi vršio proveru da li korisnik koji je poslao zahtev jeste član organizacije kojoj želi da pristupi i da li možda čak ima i odgovarajuću ulogu u sistemu za tako nešto. Jedna od implementacija bezbednog endpointa mogla bi da izgleda sledeće:

   ```
   @ApiResponse({ type: [OrganizationMemberPresenter] })
   @Get('/:organizationId/member')
   @ReadOnlyPermission()
   @HttpCode(HttpStatus.OK)
   @UseGuards(
   JwtAuthGuard,
   UserVerifiedGuard,
   PermissionGuard,
   SubscriptionGuard,
   )
   async getOrganizationMembers(
   @Req() req: any,
   @Param('organizationId') organizationId: string,
   ) {
   const isMember = await this.organizationService.isUserMemberOfOrganization(req.user.id, organizationId);

   if (!isMember) {
   throw new ForbiddenException('User is not a member of this organization.');
   }

   const users = await this.queryBus.execute(
   new GetOrganizationMembersQuery(organizationId),
   );
   return users.map((user) => new OrganizationMemberPopulatedPresenter(user));
   }
   ```

   Kao što je prikazano, pre izvršavanja same logike, vrši se provera da li je korisnik član organizacije. U slučaju da napadač dodje do postojećeg identifikatora organizacije, to neće biti dovoljno kako bi pribavio podatke o njenim korisnicima, jer on sam nije deo nje te mu pristup nije odobren. Na ovaj način povećana je bezbednost prikazanog endpoint-a, a samim tim i smanjen rizik od IDOR napada.

2. Mongoose hook-ovi u slučaju write IDOR napada [M2]

   Mongoose biblioteka nudi određen set ugrađenih hook-ova (često nazivanih i middleware-ima) koji se okidaju pre ili posle odredjenih akcija (pre i post hooks). Bitno je istaći da se hook-ovi implementiraju na nivou šeme. Česte akcije jesu save, remove i validate. Jedna od glavnih namena ovih hook-ova jeste rukovanje kontrolom pristupa. Iz navedenog da se primetiti da u slučaju smanjenja rizika od write IDOR napada od koristi mogu biti pre-hook-ovi Mongoose biblioteke. Jedan ilustrativan primer bio bi da napadač pokušava da izvrši write IDOR napad kako bi izbrisao određenog korisnika iz neke organizacije. U slučaju dobavljanja odgovarajućih identifikatora, logika remove pre-hook-a koja ne bi dozvolila neautorizovano izvršavanje ove akcije mogla bi da izgleda sledeće:

   ```
   OrganizationMemberSchema.pre('remove', async function(next) {
   const member = this;
   const currentUser = member.\_currentUser;

   if (!currentUser) {
   return next(new Error('Current user context is not available.'));
   }

   const isAuthorized = await checkUserAuthorization(currentUser, member.organizationId);

   if (!isAuthorized) {
   return next(new Error('User is not authorized to delete this organization member.'));
   }

   next();
   });
   ```

3. Indirektne reference objekta [M3]

   Umesto korišćenja direktnih referenci u korisničkim interfejsima (u analiziranom slučaju to je ObjectID), ideja je da se koriste indirektne reference. Na primer, umesto korišćenja identifikatora u URL-u, moguće je koristiti drugi skup identifikatora na osnovu kojih je moguće pristupiti podacima, a da oni nemaju bilo kakvu vezu ka ostalim objektima u bazi podataka.

4. Validacija korisnicnog unosa i sanitizacija [M4]

   Implementacija stroge validacije i sanitizacije korisnickog unosa je vazan segment kako bi se osiguralo da je unos u odgovarajucem formatu i ocekivanih vrednosti.

### MITM (Man in the Middle) [N2]

Man in the Middle napad bazira se na napadačevom presretanju komunikacije izmedju MongoDB servera i klijenta radi prisluškivanja ili izmene informacija. U slučaju neenkriptovane konekcije za komunikaciju sa MongoDB, informacije mogu biti presretnute od strane napadača. Ovo je poseban rizik ukoliko je baza podataka dostupna preko interneta. Ovaj napad je relevantan za MongoDB iz razloga što starije verzije MongoDB nisu imale podešen TLS, odnosno enkriptovanu konekciju kao podrazumevano ponašanje, što je za posledicu imalo veliki broj MongoDB servera sa nedovoljno zaštićenom komunikacijom. Takodje, pored čak i omogućene TLS konfiguracije, ukoliko je ona nepravilna ili u slučaju korištenja slabih kriptografskih protokola koje je moguće dekriptovati ostavlja prostor za napadača da iskoristi ranjivosti sistema.

Tok napada:

1. Presretanje

   Napadač započinje napad presretanjem mrežnog saobraćaja. Postoji nekoliko različitih tehnika presretanja saobraćaja od kojih su neke: - ARP Spoofing - tehnika moguća za izvedbu u slučaju kada je MongoDB hostovan u LAN mreži. Napadač može iskoristiti ovu tehniku da redirektuje saobraćaj od MongoDB servisa do svoje mašine, sto mu omogućava presretanje, izmenu ili blokiranje upita i odgovara. - DNS Spoofing - tehnika relevantna za MongoDB instance dostupne preko mreže. Ukoliko napadač uspe da kompromituje DNS podešavanja, upiti bivaju redirektovani na maliciozni server koji imitira pravu MongoDB instancu, dovodeći do presretanja i korupcije.

2. Dekriptovanje

   Nakon presretanja neophodno je da napadač preuzme kontrolu mrežnog saobracaja. Ovo je moguće izvesti koristeći nekoliko tehnika od kojih je za MongoDB relevanta SSL Stripping tehnika. - SSL Stripping - tehnika primenjiva kada konekcije sa MongoDB nisu uopšte ili pravilno konfigurisane sa TLS/SSL. Cilj SSL Stripping tehnike jeste snižavanje bezbednosti konekcije sa enkriptovane na neenkriptovanu.

#### Mitigacije

1.  TLS/SSL enkripcija konekcije [M1]

    Najvažnija mitigacija jeste obezbediti enkriptovane konekcije ka MongoDB kako bi postojala zaštita od mogućih tehnika, pogotovo SSL Stripping tehnike. Ova mitigacija uključuje korišćenje jakih šifri i savremenih protokola. TLS obezbedjuje da su podaci u tranzitu enkriptovani.

    Konfiguranje TLS (Transport Lazer Security) u slučaju Node.js aplikacije i MongoDB baze podataka koje komuniciraju koristeći Mongoose biblioteku uključuje nekoliko koraka.

    - Dobavljanje TLS sertifikata

       Pod ovim korakom mogu se razmotriti dva slučaja: self-signed sertifikati i sertifikati izdati od validnog CA (Certifikate authority). Dobra praksa je da se u produkciji koriste validni sertifikati izdati od validnih tela. Iako se i u produkciji mogu koristiti self-signed sertifikati, ovaj tip je podložan MitM napadu koji se ovde želi izbeći, te stoga taj slučaj neće biti detaljnije razradjen.

      Prvi korak predstavlja generisanje CSR (Certificate Signing Request). Ovo je moguće izvesti upotrebom nekog od alata, na primer OpenSSL. Putem OpenSSL komandi generisaće se par ključeva (javni i privatni) i CSR. Pri generisanju ključeva neophodno je specificirati algoritam za enkripciju koji će biti korišćen pri generisanju, kao i veličinu ključa. Primer kako bi komanda mogla da izgleda je sledeći:

          OpenSSL genrsa -out yourprivatekeyname.key 2048

          OpenSSL genrsa -out www_codesigningstore_com.key 2048

          U primeru je odabran RSA algoritam, kao i dužina ključa od 2048 bajtova.

          Nakon generisanja ključeva, na red dolazi i generisanje CSR-a. Primer komande za to je sledeći:

          OpenSSL req -new -key domain_com.key -out domain_com_csr.txt, odnosno specifičnije:

          OpenSSL req -new -key www_codesigningstore_com.key -out www_codesigningstore_com_csr.txt

          Naredni korak zahtevao bi unos neophodnih informacija o domenu i/ili kompaniji kako bi se CSR zahtev upotpunio. Tražene informacije za unos su:

          Common Name: Ovde je neophodno uneti kvalifikovano domensko ime čije je obezbedjivanje i cilj.

          Organization: Predstavlja legalno registrovano ime orgazacije.

          Department: Poznatije kao i organizaciona jedinica (OU - organization unit). Moguće je preskočiti unos ove informacije iz razloga što u budućnosti ova informacije neće biti deo SSL/TLS sertifikata.

          City, State/Province i Country: Za svaki od ovih podataka je potrebno uneti informacije vezane za organizaciju.

      Ovo je moguće učiniti i korišćenjem i samo jedne komande u OpenSSL, odnosno prethodno prikazane komande koja bi bila upotpunjena neophodnim informacijama. Primer kako bi takva komanda izgledala je:

   ```
      Openssl req -new -newkey rsa:2048 -nodes -out www_codesigningstore_com_csr.txt -keyout www_codesigningstore_com.key -subj “/C=US/ST=Florida/L=St.Petersburg/O=Rapid Web Services, LLC/CN=www.codesigningstore.com”
   ```

   Nakon izvršenih prethodnih koraka, preostaje još slanje CSR informacija sertifikovanom telu (CA). Potom to sertifikaciono telo koristi te priložene podatke kako bi ih validiralo i izdalo sertifikat koji će biti korišćen u sistemu za obezbedjivanje konekcije izmedju Node.js aplikacije i MongoDB baze podataka.

   - Podešavanje TLS u Mongoose konekciji

     Pre samog podešavanja TLS, neophodno je pribaviti konekcioni URI. On najčešće počinje sa 'mongodb+srv://'. Upravo ovaj format 'mongodb+srv://' indicira da će se konekcija osigurati putem TLS-a. Primer kako bi u kodu izgledala konfiguracija TLS za Mongoose je sledeća:
        
      ```
          const mongoose = require('mongoose');
          const mongoDBUri = 'mongodb+srv://yourusername:yourpassword@yourcluster.yourprovider.com/yourdbname';

          mongoose.connect(mongoDBUri, {
             useNewUrlParser: true,
             useUnifiedTopology: true,
             ssl: true
          });
      ```

2.  Validacija sertifikata

    U slučaju kada se TLS koristi i komunikacija jeste enkriptovana, krucijalno je da se pravilno vrši validacija sertifikata. Neopdhodna je provera validnosti, datuma isteka kao i tela koje je izdalo taj sertifikat. Na ovaj način može se smanjiti rizik od MitM napada, koji bi se izvodio na način da napadač podmeće lažni sertifikat predstavljajući se kao legitiman server i na taj način održavajući konekciju. Mongoose biblioteka se sama brine o ovome, odnosno podrazumevano ponašanje je da vrši validaciju TLS sertifikata prema sertifikacionom telu.

3.  Mere bezbednosti mreže [M2]

    Implementacija snažnih mera bezbednosti mreže predstavlja izuzetno važnu mitigaciju protiv MitM napada i mogućih tehnika za njegovu izvedbu. Ova stavka uključuje primenu Firewall-a i VPN-a, koji mogu pomoći pri smanjenju rizika od ARP i DNS Spoofing tehnika.

4.  Monitoring [M3]

    Neizostavna mitigacija koja igra ključnu ulogu pri detekciji i samim tim odgovoru na potencijalne MitM napade.

### DoS napad [N3]

Denial of Service predstavlja pretnju koja ukoliko se realizuje rezultuje onemogućavanjem normalnog funkcionisanje servera, odnosno da postaje nedostupan svojim korisnicima. Prethodno navedeno direktno narušava stavku dostupnosti u CIA trijadi. Napadač je u mogućnosti da ovo izvede na nekoliko različitih načina, gde svaki eksploatiše različit aspekt sistema baze podataka.

- Različiti napadi za realizaciju DoS pretnje

1. Resource Exhaustion

   Cilj ovog napada je preopterećenje MongoDB servera sa intezivnim operacijama. Napadači se služe kompleksnim upitima koji intezivno troše CPU moć, memoriju itd dovodeci do usporenja servera ili pada. Primer ovakvih upita jesu duboko ugnježdeni agregacioni upiti, gde svaki nivo podupita vrši operacije kao sto su otpakivanje nizova, vršenje višestrukih spajanja ili sortiranje velikog broja podataka.

2. Connection Saturation

   MongoDB ima limitiran broj konkurentnih konekcija koje može da podrži. Cilj napadača jeste da onemogući server da rukuje sa novim konekcijama na način da pokušava da otvori koliko god je moguće novih konekcija ka MongoDB serveru (često preopterećujući server i bazu ogromnim brojem zahteva), dostižući limit. Napadač uspeva da održi ove konekcije otvorene šaljući minimalan broj podataka povremeno. Posledica ovoga jeste da baza prestaje da odgovara redovnim korisnicima jer je maksimalan broj konekcija dostignut, a nijedna se ne oslobadja.

   Posmatrajući sistem koji se analizira i uzevši u obzir da je u pitanju Node.js aplikacija koja ostvaruje komunikaciju sa MongoDB bazom podataka posredstvom Mongoose biblioteke, važno je istaći relevantne informacije za ove tehnologije. Prilikom otvaranja konekcije sa MongoDB putem Mongoose, stvara se takozvani pool konekcija (tačan broj konekcija može biti eksplicitno konfugurisan). Connection pooling mehanizam pruža veću efikasnost, obzirom da održava konekcije aktivne i iznova ih koristi uzimajući konekciju iz pool-a kada je potrebna za izvršavanje operacije i nakon završetka iste vraća se u pool, umesto otvaranja i zatvaranja konekcije pri svakoj operaciji. Sledi primer kako maksimalan broj konekcija, kao i maksimalno vreme koje konekcija provodi neaktivna (idle time) može biti podešeno koristeći Mongoose i atribut poolSize i socketTimeoutMS:

   ```

   mongoose.connect(uri, {
   useNewUrlParser: true,
   useUnifiedTopology: true,
   poolSize: 10, // maksimalan broj konekcija je u ovom primeru 10
   socketTimeoutMS: 30000 //definisano u milisekundama, dakle max idle time po konekciji je 30s
   });
   ```

   Specifičan tip connection saturation napada bio bi Slowloris napad. Važno je napomenuti da ovaj napad ne targetira bazu direktno, već aplikativni sloj. Razlikuje se od standardnog saturation attack napada po tome što umesto pokušaja da preoptereti server sa velikim brojem zahteva u kratkom vremenskom roku, Slowloris se fokusira na otvaranje konekcija i održavanjem ih aktivnih koliko god je moguće dugo. Ovaj napad bazira se na slanju zahteva koji su sporiji nego obični imitirajući redovni saobraćaj. Kao što je prethodno navedeno, server ima odredjen broj konekcija dostupan, gde svaka od njih ostaje 'živa' pokušavajući da završi spori zahtev, što se nikad neće dogoditi u slučaju Slowloris napada. Kada se dostigne maksimalan broj konekcija koje server može da podrži, svaka dodatna konekcija neće biti realizovana te dolazi do ostvaranja Denial of Service pretnje.

   - Koraci Slowloris napada:

   1. Napadač otvara višebrojne konekcije ka serveru slanjem višebrojnih parcijalnih zaglavlja HTTP zahteva.

   2. Server upošljava konekciju za svaki pristigli zahtev, sa namerom oslobadjanja iste nakon izvršenog zahteva. Kao što je prethodno spomenuto, moguće je specificirati maksimalno vreme koje konekcija provodi neaktivna, pre oslobadjanja iste. Dakle, ukoliko konekcija provede odredjeno vreme neaktivna, server će reagovati oslobadjanjem te konekcije kako bi mogla da obradi neki drugi zahtev.

   3. Kako bi napadač sprečio da se dogodi oslobadjanje konekcije pri neaktivnosti, on periodično šalje parcijalna zaglavlja zahteva serveru kako bi održao konekciju živom, imitirajući spor zahtev.

   4. Rezultat prethodnog koraka jeste da server nikad ne može da oslobodi ove postojeće konekcije, jer ne dolazi do isteka definisanog vremena u stanju neaktivnosti niti se zahtev ikada završava. Jednom kad su sve konekcije zauzete, server neće biti u mogućnosti da odgovori na nove zahteve koji pristižu od legitimnih korisnika, rezultujući ostvarenom DoS pretnjom.

4. JavaScript Execution

   MongoDB dozvoljava izvršavanje Javascript izraza ili funkcije za odredjene operacije, od kojih je jedna $where operator. Ukoliko se korisnički unos ne validira ili ne sanitizuje, moguće je da dodje do injektovanja malicioznog JavaScript koda koji bi izvršavao resursno zahtevne operacije, dovodeći do neresponzivnosti servera ili njegovog potpunog pada.

#### Mitigacije

1. Ograničavanje kompleksnosti upita [M1]

   Ograničavanjem kompleksnosti upita sprečava se mogućnost iscrpljivanja resursa servera izvršavanjem kompleksnih upita i dugotrajnih operacija. Ova mitigacija direktno onemogućava Resource Exhaustion napad.

2. Onemogućavanje izvršavanje Javascript-a [M2]

   Ukoliko za funkcionisanje sistema nije neophodno izvršavanje JavaScript-a, bitna stavka je onemogućiti izvršavanje JavaScript-a u MongoDB kako bi se direktno sprečio JavaScript Execution napad.

3. Rate limiting, smanjenje timeouta [M3]

   Ograničavanje pristupa na osnovu odredjenih faktora i načina korišćenja servera mogu biti značajna mitigacija u slučaju Slowloris napada. Tehnika kao što je ograničavanje maksimalnog broja konekcija koje jedna IP adresa može da zauzme, kao i potencijalno smanjenje timeouta za konekciju neki su od načina za mitigaciju tog napada.

4. Korišćenje reverse proxy-ja

   Reverse proxy je server koji stoji ispred targetiranog servera i prosledjuje pristigle zahteve originalnom serveru. U suštini zahtev ne stiže direktno do servera već do proxy-ja koji potom njemu prosledi zahtev. Nakon što server obradi zahtev, odgovor vraća proxy-ju, koji ga zatim prosledjuje klijentu. Važno je napomenuti da klijent ni u jednom momentu nije svestan postojanja reverse proxy-ja. Neke od benefita korišćenja reverse proxy-ja jesu load balancing, povećana bezbednost, rukovanje SSL enkripcijom i dekripcijom, keširanje. U ovom svetlu posebno je interesantan kao značajna mitigacija Slowloris napada, obzirom da su ovi reverse proxy-ji konfigurisani da izdrže veliki broj paralelnih konekcija. Takodje, mogu biti konfigurisani sa restriktivnijim timeout podešavanjima za konekcije. Mogu brzo da zatvore konekcije koje su previše spore ili neaktivne, oslobadjajući ih za nove operacije. Isto tako, važno je istaći da reverse proxy ima mogućnost da čeka dok zahtev nije kompletan pre prosledjivanja istog targetiranom serveru, što predstavlja direktnu mitigaciju Slowloris napada.

5. Redovno ažuriranje MongoDB [M5]

   Kako su security patch-evi često deo ažuriranja, važno je redovno ažurirati verziju MongoDB-a, kako ne bi postojala mogućnost za napadača da eksploatiše ranjivosti koje su vec rešene.

6. Alokacija resursa i monitoring [M6]

   Cilj navedene mitigacije je da se resursi pravilno alociraju (CPU, RAM memorija, prostor na disku) kako bi uspešno obradjivali očekivan broj zahteva. Pored toga, monitoring pruža dobar uvid u praćenje stanja ovih resursa i omogućava detektovanje znakova iscrpljivanja navedenih resursa.

### Reference

1. https://data-flair.training/blogs/mitm-attack-types-prevention/?fbclid=IwAR3XWpc4QkTMM1UlLq_pws6W24FHyTgX0SlTovD1oXsiLUOH_LS4R-Xww98
2. https://www.mickaelwalter.fr/idor-with-mongodb-understanding-objectid/?fbclid=IwAR2kWbUp9-cf2SuWvbnhz3eb0dql_UEz-5PZhNnBPGxdaxbeLSTw2OZ47Lo
3. https://www.slideshare.net/APIsecure2/2022-apisecuremethod-for-exploiting-idor-on-nodejsmongodb-based-backend
4. https://book.hacktricks.xyz/pentesting-web/idor
5. https://infonomics-society.org/wp-content/uploads/ijds/published-papers/volume-8-2017/Security-Vulnerabilities-of-NoSQL-and-SQL-Databases-for-MOOC-Applications.pdf
6. https://owasp.org/www-community/attacks/Denial_of_Service
7. https://codesigningstore.com/how-to-generate-csr-using-openssl
8. https://mongoosejs.com/docs/tutorials/ssl.html
9. https://www.youtube.com/watch?v=XiFkyR35v2Y&fbclid=IwAR1Izu47oX2guqvkGLfgPuRceUOXcBc1rHbpisXMYlMLW3xMsNSNrSJAlZQ
10. https://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/
