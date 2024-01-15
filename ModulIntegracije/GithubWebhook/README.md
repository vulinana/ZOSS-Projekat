# Github Webhook App integrisana sa Github API-jem

Github webhook app je aplikacija čija je glavna funkcionalnost integracija sa Github API-jem radi pribavljanja podataka. Podaci koji se prikupljaju komunikacijom sa ovim eksternim servisom jesu podaci o organizacijama, repozitorijumima i svim vrstama contribution-a u tim repozitorijumima. Github webhook-ovi su HTTP callback-ovi koji se koriste kako bi se sistemi integrisani sa Github API-jem obavestili nakon odredjenih dogadjaja (push, pull request, otvaranje issue-a itd).

Neke od postojećih pretnji vezane za sistem integrisan sa GitHub-om:

1. Kradja i manipulacija podacima [P1]

   Kradjom i manipulacijom podataka direktno je narušen princip autentičnosti u CIA trijadi. Bilo da se radi o kradji ličnih i osetljivih podataka, koje potom može da zloupotrebi na različite načine ili o manipulaciji tačnosti podataka, posledica je kompromitovanost sistema.

2. Nedostupnost sistema [P2]

   Dostupnost sistema jedan je od principa CIA trijade koji garantuje da je sistem uvek dostupan korisniku kada mu je potreban. Nivo nedostupnosti sistema koji se toleriše je varijabilan u odnosu na kritičnost sistema. U analiziranom slučaju, replay napad može direktno da ugrozi dostupnost sistema.

![image](https://github.com/vulinana/ZOSS-Projekat/assets/88163410/e6d57bf3-a111-4cdc-b714-02428cfb599a)


## Napadi

### 1. Fake Webhook Request Attack [N1]

Fake webhook request attack je napad vezan za sisteme koji vrše integraciju sa GitHub API-jem. Suština ovog napada bazira se na tome da napadač šalje malicionizan HTTP zahtev na webhook endpoint sistema koji se integriše sa Github API-jem. Navedeni napad ima nekoliko koraka:

1. Identifikacija mete

   Napadač pokušava da pronadje sistem integrisan sa GitHub-om putem webhook-ova.

2. Kreiranje malicioznog zahteva

   Napadač kreira lažan HTTP zahtev koji imitira formatom i strukturom legitiman zahtev koji bi pristigao od Github-a. Ovaj zahtev moze da uključi maliciozni payload čija je svrha da eksploatiše ranjivosti u sistemu.

3. Izvršavanje malicioznog payload-a

   Kako je slučaj da github potpisuje svoje webhook zahteve, napadač može pokušati da lažira potpis. U slučaju da sistem nema mehanizam za validaciju i autentifikaciju pristiglog webhook zahteva, sistem će isprocesirati maliciozni payload. Ovo izvršavanje može rezultovati kradjom podataka, izvršavanjem malicioznog koda ili neplaniranim akcijama. U nastavku sledi prikaz strukture Github Webhook POST zahteva koji napadač mora ispoštovati kako bi izvršio napad sa lažnim zahtevom.

   Zaglavlja:

   - X-GitHub-Event: Naziv dogadjaja koji je okinuo webhook (push, pull request, issues, fork, star, watch itd)

   - X-GitHub-Hook-ID: jedinstveni identifikator webhook-a

   - X-GitHub-Delivery: Globalni jedinstveni identifikator (GUID) za identifikaciju dostave.

   - X-Hub-Signature: Ovo zaglavlje se šalje ukoliko je webhook konfigurisan sa secret-om. Od ključne važnosti za analizirani napad, obzirom da se validacijom vrednosti ovog zaglavlja može potvrditi legitimnost pošiljaoca. Vrednost predstavlja SHA-1 i secret heširanu vrednost tela zahteva. Iako se preporučuje korišćenje X-Hub-Signature-256 zahteva zbog povećane bezbednosti, ovo zaglavlje je i dalje prisutno zbog kompatibilnosti sa već postojećim integracijama.

   - X-Hub-Signature-256: Za ovo zaglavlje važi isto kao i za prethodno, jedina razlika je u tome što se vrednost generiše korišćenjem SHA-256 heš funkcije sa secret-om.

   - User-Agent: uvek ima vrednost 'Github-Hookshot/'

   - X-GitHub-Hook-Installation-Target-Type: Tip resursa gde je webhook kreiran.

   - X-GitHub-Hook-Installation-Target-ID: Jedinstveni identifikator resursa gde je webhook kreiran.

   Primer kako bi izgledao Webhook POST zahtev uzevši u obzir sve prethodno navedeno:
   ```
    POST /payload HTTP/2

    X-GitHub-Delivery: 72d3162e-cc78-11e3-81ab-4c9367dc0958
    X-Hub-Signature: sha1=7d38cdd689735b008b3c702edd92eea23791c5f6
    X-Hub-Signature-256: sha256=d57c68ca6f92289e6987922ff26938930f6e66a2d161ef06abdf1859230aa23c
    User-Agent: GitHub-Hookshot/044aadd
    Content-Type: application/json
    Content-Length: 6615
    X-GitHub-Event: issues
    X-GitHub-Hook-ID: 292430182
    X-GitHub-Hook-Installation-Target-ID: 79929171
    X-GitHub-Hook-Installation-Target-Type: repository

    {
       "action": "opened",
       "issue": {
       "url": "https://api.github.com/repos/octocat/Hello-World/issues/1347",
       "number": 1347,
       ...
       },
       "repository" : {
       "id": 1296269,
       "full_name": "octocat/Hello-World",
       "owner": {
       "login": "octocat",
       "id": 1,
       ...
       },
       ...
       },
       "sender": {
       "login": "octocat",
       "id": 1,
       ...
       }
   }
   ```
   Uzevši u obzir sve prethodno navedeno, cilj napadača može biti slanje lažnih Github webhook zahteva bez malicioznih Javascript injektovanih kodova, obzirom na analizirani sistem (prikaz statistike aktivnosti članova u organizaciji). Obradom lažnog zahteva, podaci koje bi analizirani sistem prikazivao ne bi bile tačne, pa bi samim tim integritet podataka bio narušen, potencijalno zajedno sa poverenjem korisnika sistema. Ovo bi moglo predstavljati 'blaži' vid napada koji bi mogao biti izvršen, medjutim postoji šansa da napadač ima veći cilj od ovoga. Na primer, injektovanjem malicioznog Javascript koda umesto vrednosti odredjenog polja u telu zahteva, a ukoliko se ne vrši sanitizacija podataka u sistemu, može izazvati razne neželjene efekte, od kradje podataka do neplaniranog ponašanja sistema.

#### Mitigacije

1. Validacija payload-a [M1]

   Github potpisuje svoje zahteve sa secret-om koji se čuva u eksternom sistemu. Dakle, Github koristi taj secret kako bi kreirao hash potpis payload-a, koji se šalje u X-Hub-Signature header-u. Kada na eksterni sistem pristigne zahtev potrebno je da sistem validira zahtev koristeći taj secret. Sistem preračunava hash payload-a pristiglog zahteva koristeći istu metodu kao i Github (to je uglavnom SHA256). Nakon što izračuna hash, dovoljno je da ga uporedi sa hash-om koji je pristigao u X-Hub-Signature header-u zahteva. Ukoliko se hash-evi podudaraju može se zaključiti da se zahtev zaista poslat od Githuba i preći na obradu istog. Naravno, ukoliko se hash-evi ne podudaraju zahtev ili nije poslat od strane Github-a ili je zahtev u toku transporta menjan, te će zahtev biti odbijen od strane servera. Primer kako bi mogla da izgleda validacija pristiglog webhook zahteva u express.js:
   ```
    app.post('/webhook', (req, res) => {
       const signature = req.headers['X-Hub-Signature'];
   
       if (!signature) {
          return res.status(403).send('No signature');
       }
   
       const event = req.headers['X-GitHub-Event'];
       const delivery = req.headers['X-Github-Delivery'];
   
       const payload = JSON.stringify(req.body);
       if (!payload) {
          return res.status(400).send('Request body empty');
       }
   
       // Validacija potpisa uz pomoć uskladištenog github secret-a
       const expectedSignature = `sha1=` +
       crypto.createHmac('sha1', GITHUB_SECRET)
       .update(payload)
       .digest('hex');
   
       if (signature !== expectedSignature) {
          return res.status(401).send('Invalid signature');
       }
   
       // Procesiranje github dogadjaja ukoliko je potpis validan
       ...
   
       res.status(200).send('Request received');
    });
   ```
2. Povećanje sigurnosti endpointa [M2]

   Ukoliko je moguće, dobra je praksa limitirati ko ima pristup odredjenom endpointu, gde bi u ovom slučaju to predstavljao endpoint za Github webhook. Takodje, monitoring neobičnih zahteva bi mogao predstavljati pomoć u identifikovanju lažnih zahteva.

3. Redovna rotacija secret-a [M3]

   Periodična promena secreta sa kojim se payload potpisuje smanjuje rizik da se dogodi korišćenje kompromitovanog secret-a od strane napadača u lažnim zahtevima.

4. Koriscenje WAF-a (Web Application Firewall) [M4]

   Korišćenje WAF-a može pomoći pri identifikaciji i filterovanju malicioznih napada na osnovu poznatih šablona napada i pružiti dodatan sloj zaštite od kompleksnih napada.

### 2. Repository Tampering [N2]

Rizik od repository tampering napada u slučaju servisa integrisanog sa Github-om nije zanemarljiv. Ovaj napad se bazira na neautorizovanim izmenama sadržaja u repozitorijumima, čije podatke servis dobavlja. Iz razloga što se webhook-ovi automatski izvršavaju, sve izmene načinjene u repozitorijumu, završavaju u servisu integrisanom sa Github-om.

Napad započinje od toga da napadač prvo uspeva da neovlašćeno pristupi Github repozitorijumu. Neki od načina na koji napadač može to da ostvari jesu kompromitovani korisnički kredencijali, ekploatacija podešavanja u repozitorijumu ili putem socijalnog inženjeringa.

U zavisnosti od naloga koji je kompromitovan od strane napadača razlikuju se dva scenarija:

1. Napadač je kompromitovao nalog koji ima permisije za udaljeno izvršavanje promena u repozitorijumu, ali nema direktan pristup serveru repozitorijuma ili njegovom fajl sistemu. U ovom slučaju mogućnosti su više ograničene, medjutim napadač i dalje ima moć da komituje maliciozan kod ili menja istoriju. Dodatno, ukoliko je CI/CD pipeline podešen, te maliciozne promene mogle bi biti automatski deployovane, a samim tim ubrzo bi završile i u integrisanom sistemu.

2. U slučaju da je napadač kompromitovao nalog sa većim permisijama, odnosno dozvolu za pisanje u server repozitorijuma i fajl sistem, on ima više slobode za maliciozno ponašanje. Napadač je u mogućnosti da menja fajlove repozitorijuma ili konfiguraciju servera, što dovodi do automatskih promena. Obzirom da ima pristup serveru, potencijalno može da instalira malware ili pribavlja podatke. Takodje, postoji opcija da sam sebi poveća privilegije obzirom na pristup fajl sistemu.

Maliciozni kod ubačen prvo u repozitorijum, putem webhook zahteva završava i u sistemu koji se integrisao sa Github-om. Takav kod moze da izvrši razne operacije u posmatranom sistemu, od kradje podataka, brisanja istih ili dovede do promene ponašanja sistema. Obzirom na analizirani sistem, tu bi postojala opasnost od injektovanja malicioznog koda npr. u commit poruci ili naslovu pull request-a, obzirom da integrisani sistem to pribavlja. Napadač bi mogao izvesti ovo ukoliko na strani sistema ne postoji nikakva sanitizacija podataka, pre njihovog skladištenja ili obrade. Pored malicioznog koda, postoji i aspekt injektovanja malicioznog URL-a u commit poruci, koja bi se u slučaju Caddie sistema prikazivala direktno korisnicima i nakon potencijalnog pritiska na isti korisnici bi kompromitovali svoju bezbednost. Ovaj tip injektovanja u suštini rezultira XSS napadom. Ovaj napad se bazira na tome da napadač injektuje maliciozni kod na veb stranice kojima korisnik pristupa. U analiziranom sistemu korisnicima se direktno prikazuju sadržaji commit poruka koji se čuvaju u bazi podataka ovog sistema. Kada se maliciozni sadržaj skladišti u sistemu to potpada pod odredjen tip XSS napada koji se zove Stored XSS (Persistent XSS). Naravno, ključ da napadač može ovo da izvrši leži u lošoj/nepostojećoj sanitizaciji u sistemu.

#### Mitigacije

1. Logovanje webhook dogadjaja [M1]

   Na ovaj način moguće je ispratiti sve dogadjaje i potencijalno primetiti neočekivane aktivnosti, kao što su velike promene nad izvornim kodom ili komiti od strane nepoznatih korisnika.

2. Alert sistem [M2]

   Implementacijom alert sistema integrisani sistem bio bi obavešten u slučaju neobičnih aktivnosti u repozitorijumu koje bi mogle biti posledica repository tampering napada.

3. Rollback plan [M3]

   Obzirom da se webhook zahtevi izvršavaju automatski cim se dese dogadjaji koji su interesantni za integrisani sistem, ukoliko se izvrši repository tampering napad, promene bi se ubrzo našle i u drugom sistemu. Zato je neophodno postojanje spremnog rollback plana koji će se izvršiti čim se utvrdi da je došlo do napada kako bi se sistem vratio u prethodno legitimno stanje (postojanje backup-a je ključno).

4. Sanitizacija [M4]

   Prethodno navedeni primer za injektovanje malicioznog URL može se izbeći sanitizacijom commit poruka pristiglih u webhook zahtevu. Jedan od načina na koje je ovo moguće izvesti jeste upotrebom Regex izraza. Primer kako bi se navedena sanitizacija mogla izvesti je sledeći:
   ```
   function sanitizeCommitMessage(commitMessage) {
      // Regex izraz koji proverava da li commit poruka sadrži link
      const urlRegex = /https?:\/\/[^\s]+/g;
   
      // Menja sadržaj url-a sa praznim karakterom
      return commitMessage.replace(urlRegex, '');
   }
   
   app.post('/webhook', (req, res) => {
      if (req.body.commits && req.body.commits.length > 0) {
         req.body.commits.forEach(commit => {
         // Sanitizacija svake commit poruke u zahtevu
         commit.message = sanitizeCommitMessage(commit.message);
         });
      ...
      }
   
      res.status(200).send('Webhook processed');
   });
   ```

### 3. Replay Tampering [N3]

Replay Tampering u slučaju sistema integrisanog sa GitHub-om putem webhook-ova zasniva se na ponovnom ili odloženom slanju validnih zahteva. Obzirom da se analizirani sistem oslanja na podatke dobavljene od GitHub za statističku obradu, ponovljeni zahtevi direktno se odražavaju na statistiku koja neće prikazivati tačne podatke korisnicima.

Napadač započinje napad presretanjem validnog webhook zahteva koji GitHub šalje sistemu. Presretnut zahtev sadrži čitav payload (kao sto su informacije o komitima, push ili pr dogadjajima) zajedno sa svim header-ima, od kojih je glavni X-Hub-Signature header koji sadrži potpis payload-a neophodan za verifikaciju zahteva.

Nakon sto je zahtev uspešno presretnut od strane napadača, on je u stanju da iskoristi taj isti zahtev neograničen broj puta, što može izazvati neželjeno ponašanje i prikaz netačnih informacija u integrisanom sistemu ukoliko nisu implementirani odgovarajući mehanizmi zaštite protiv navedenog napada.

#### Mitigacije

1.  Implementacija timestamp-a [M1]

    Uključivanjem timestamp-a u payload poslatog zahteva, a potom i uvodjenje vremenskog praga koji bi specificirao da zahtevi stariji od navedenog praga nece biti prihvaćeni značajno bi smanjili mogućnost za izvodjenje replay napada. Ograničenje u pogledu korištenih tehnologije jeste to da Github ne pruža mogućnost da se timestamp vrednost direktno uključi u payload zahteva. Ovo bi se moglo rešiti korištenjem proxy-ja koji bi presretao zahtev poslat od Github-a i postavljao vrednost timestamp-a u payload zahteva. Primer kako bi izgledala validacija timestamp-a pristiglog Github webhook zahteva u Express.js:
   ```
    app.post('/webhook', (req, res) => {
       const receivedTime = Date.now();
       const maxDelay = 300000; // 5 minuta postavljeno kao vremenski prag

        // Check the time difference
        if (receivedTime - req.body.receivedTime > maxDelay) {
            return res.status(400).send('Request expired');
        }

        ...

        res.status(200).send('Webhook processed');

    });
   ```

2.  Korišćenje nonce-a [M2]

    Nonce (number used once) predstavlja jedinstveni broj koji se može slati u payload-u ili posebnom header-u zahteva. Neophodno je da na strani sistema koji je integrisan sa GitHubom postoji baza podataka u kojoj bi se skladištile sve vrednosti nonce-a pristigle u zahtevima. Validacija bi uključivala proveru nonce vrednosti pristiglog zahteva sa vrednostima u bazi podataka. Ukoliko se vrednost ne poklapa ni sa jednom postojećom, zaključuje se da je zahtev validan, u suprotnom može se pretpostaviti da se radi o ponovljenom zahtevu. U slučaju integracije sistema sa Github-om, kao nonce vrednost mogla bi se koristiti i vrednost X-Hub-Signature zaglavlja, koje je takodje jedinstveno za svaki zahtev. Naravno, kao što je već spomenuto, sa strane servera bilo bi neophodno skladištenje X-Hub-Signature vrednosti od pristiglih zahteva u bazu podataka kako bi validacija bila moguća za sprovesti. Primer kako bi validacija mogla izgledala u analiziranom sistemu je sledeći:

   ```
    @Post()
    async handleWebhook(@Req() req: Request, @Res() res: Response) {
          const signature = req.headers['x-hub-signature-256'] as string;

         if (!signature) {
            return res.status(HttpStatus.BAD_REQUEST).send('No signature provided');
         }

         // Provera da li u bazi podataka već postoji vrednost X-Hub-Signature
         const exists = await this.dbService.checkSignature(signature);
         if (exists) {
            return res.status(HttpStatus.FORBIDDEN).send('Signature has already been used');
         }

         // Ukoliko je vrednost validna, skladišti se u bazi podataka
         await this.dbService.storeSignature(signature);

         ...

         return res.status(HttpStatus.OK).send('Webhook processed');

    }
   ```

3.  HTTPS komunikacija [M3]

    U slučaju korišćenja HTTPS umesto HTTP sav sadržaj bio bi enkriptovan, te je presretanje podataka otežano, medjutim ukoliko se ono uspešno obavi, HTTPS ne može direktno da spreči replay napad.

4.  Rate limiting [M4]

    Implementiranjem rate limiting-a na webhook endpoint, ograničava se broj zahteva koji mogu biti prihvaćeni i obradjeni u odredjenom vremenskom intervalu od strane servera. Na ovaj način direktno se sistem moze zaštiti od DoS pretnje koja može biti realizovana putem replay napada.

5.  Monitoring [M5]

    Ova mitigacija može da ukaže na neobičnu aktivnost koja se dogadja u sistemu, kao sto je slanje ponovljenih zahteva u kratkom vremenskom periodu.

### Reference

1. https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
2. https://blog.korelogic.com/blog/2014/06/26/repository_tampering
3. https://hookdeck.com/webhooks/guides/webhook-security-vulnerabilities-guide
4. https://ngrok.com/blog-post/get-webhooks-secure-it-depends-a-field-guide-to-webhook-security
5. https://www.linkedin.com/pulse/attack-methods-webhook-calls-vartul-goyal/
6. https://docs.github.com/en/webhooks/webhook-events-and-payloads
