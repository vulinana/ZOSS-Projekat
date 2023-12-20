# AWS S3 eksterni servis

Amazon Simple Storage Service (S3) je usluga za skladištenje podataka u oblaku. Dostupan je u različitim AWS regijama širom sveta. Svaka AWS regija je fizički odvojena lokacija sa svojim resursima i infrastrukturom. Korisnici mogu da odaberu AWS regiju u kojoj žele da uspostave svoje skladište podataka. Bucket je osnovna jedinica organizacije podataka koji ima jedinstveno ime unutar AWS regije. Svaki bucket ima objekte, a objekat ima jedinstveni ključ unutar bucket-a. Ključ objekta predstavlja njegovu putanju unutar bucket-a kao i njegov jedinstveni identifikator. Objekat je osnovna jedinica podatka koji se čuva.<br>
Kao i svaki drugi servis tako je i AWS S3 podložan sigurnosnim pretnjama.
1. Neovlašćeni pristup osetljivim podacima [P1] <br>
Ključni resurs koji može biti ugrožen u okviru AWS S3 usluge su bucket-i sa svojim podacima. Napadač može da pregleda podatke unutar bucket-a i na taj način, ugrožava poverljivost informacija. Ovi podaci predstavljaju vredan resurs za napadača koji ih može iskoristiti u cilju zloupotrebe, iznude ili ucene gde napadač traži novac ili nešto drugo kako ih ne bi objavio ili zloupotrebio.
2. Gubitak kontrole nad bucket-om [P2] <br>
Kao i u prethodnoj pretnji, ključni resurs koji je ugrožen jeste bucket sa svojim podacima. Pored ugrožavanja poverljivosti informacija, direktno su ugroženi i integritet i dostupnost podataka smešteni unutar njega. Napadač ima mogućnost da pregleda, menja ili briše podatake, kao i da dodaje zlonamerni sadržaj i na taj način izvodi druge napade kao što je Phishing. Na ovaj način napadač može da nanese štetu organizaciji, zloupotrebi podatke, vrši ucene ili iznude finansijskih sredstava. 

![Stablo napada](https://github.com/vulinana/ZOSS-Projekat/blob/main/ModulPoslovanja/AWS-S3/Dijagrami/AWS-S3-attack-tree.png)

## Napadi

### Data Exfiltration N1

Data exiltration, poznat kao i data extrustion, predstavlja neovlašćeni prenos ili krađu podataka koji su smešteni u S3 bucket-ovima od strane napadača. Napadač pokušava dobiti pristup osetljivim podacima koje se nalaze u bucket-ovima, pa ih preneti ili zloupotrebiti.

Napadač prvo identifikuje AWS S3 bucket koji će mu biti cilj napada. Ovaj korak uključuje istraživanje dostupnih bucket-ova i procenu da li su podaci unutar njih vredni. Nakon toga sledi detaljna analiza bezbednosnih mera kako bi se identifikovale ranjivosti. Kradjom autentifikacionih podataka, manipulacijom pravilima pristupa ili korišćenjem ranjivosti napadač pokušava dobiti neovlašćeni pristup bucket-u. Nakon što je ostvario pristup podacima, napadač identifikuje osetljive podatke, a zatim ih prenosi na neku drugu lokaciju pod svojom kontrolom. Nakon izvršavanja napada, napadač može pokušati da sakrije tragove kako bi sprečio da bude otkriven. To će učiniti brisanjem logova i evidencije aktivnosti. Nakon svih ovih koraka napad je izvršen i napadač može da iskoristi podatke u skladu sa svojim ciljevima. Na ovaj način Data Exfiltration ostvaruje pretnju 'Neovlašćeni pristup osetljivim podacima' [P1]. Napadač može da proda osetljive informacije na crnom tržištu, da vrši iznudu ili ucenu onoga kome je podatke ukrao.

#### Mitigacije

1. Konfiguracija pristupa [M1] <br>
Kada je konfiguracija pristupa u pitanju, potrebno je odrediti ko ima pristup kojim podacima i na koji način. Ovo podrazumeva razna podešavanja kao sto su postavljanje Identity and Access Managment - IAM politika, Bucket-Level politika, postavljanje S3 Bucket Access Control Lists - ACL-ova.<br><br>
**IAM politike** - određuju koje su radnje dozvoljene ili odbijene na AWS uslugama/resursima za određenog korisnika. IAM politike možemo da dodelimo          specifičnom korisniku, ulozi ili grupi.<br><br>
**Bucket-Level politike** - određuju koje su radnje dozvoljene ili nisu nad specifičnim bucket-om za određene korisnike. <br><br>
**S3 Bucket ACL** - predstavlja stari način upravljanja pristupom bucket-ima. AWS preporučuje korišćenje IAM ili Bucket-Level politika, ali još uvek postoje slučajevi u kojima ACL-ovi daju veću fleksibilnost od politika. To je jedan od razloga zašto još uvek nisu zastareli niti će biti uskoro. Najznačajnija prednost jeste što se mogu dodeljivati i bucket-ima ali i samim objektima, što nije slučaj sa politikama. Znači da postoji velika fleksibilnost nad resursima jer neki objekti mogu biti javni u privatnom bucket-u kao i obrnuto. <br><br>
Kada je u pitanju Data Exfiltration najviše pažnje treba posvetiti dozvolama za čitanje podataka (READ). Najbolja praksa, bez obzira koje se od ova tri podešavanja koristi, predstavlja primenu dozvola sa najmanjim privilegijama, što znači da korisnici dobijaju samo dozvole koje su im neophodne za obavljanje sopstvenih zadataka. <br><br>
3. Enkripcija podataka [M2] <br>
Enkripcijom podaci postaju beskorisni napadaču jer ne može da ih pročita. Postoji nekoliko načina kako se može odraditi enkripcija kada je u pitanju AWS S3. <br><br>
**Šifrovanje na strani servera** - Amazon S3 šifruje objekte pre nego što ih sačuva na diskovima u svojim centrima podataka, a zatim dešifruje objekte kada budu preuzeti. Šifrovanje se vrši uz pomoć ključa koji se ne čuva na istom mestu gde su i podaci. Amazon S3 nudi nekoliko opcija za šifrovanje na strani servera kao što su: šifrovanje pomoću Amazon S3 managed keys (SSE-S3), AWS Key Managment Service keys (SSE-KMS) i pomoću ključa koji obezbeđuje korisnik (SSE-C). <br><br>
**Šifrovanje na strani klijenta** - podrazumeva da korisnik pošalje već šifrovane podatke na Amazon S3. U ovom slučaju on upravlja procesom šifrovanja, ključevima za šifrovanje i povezanim alatima. 

### Bucket Enumeration <a id="N2">[N2]</a>

Bucket Enumeration je napad koji podrazumeva otkrivanje postojanja S3 bucket-a i proveru da li su oni javni. Ovaj napad je važan korak za napadače koji planiraju potencijalne napade na podatke koji se nalaze u tim bucket-ima (kao što je Data Exfiltration [N1] ili Bucket Takeover [N3]). Medjutim može biti i deo bezbednosne analize sa ciljem otkrivanja potencijalnih rizika.

Napad počinje sa identifikacijom AWS regije u kojoj će se tražiti bucket-i. Bitno je odabrati pravu regiju jer različite regije imaju različite bucket-e. Nakon odabira regije, napadač pretražuje bucket-e. To može da radi koristeći AWS CLI (aws s3 ls - izlistava dostupne bucket-e u regiji), skripte kako bi generisao moguća imena bucket-a (nasumične kombinacije ili koristeći rečnike sa često korišćenim imenima), alate koji omogućavaju automatsko pretraživanje i identifikaciju dostupnih bucket-a (S3Scanner, Bucket Finder itd). Nakon što je pronađen javno dostupan bucket, ostvarena je pretnja 'Neovlašćen pristup osetljivim podacima' [P1].

#### Mitigacije

1. Konfiguracija pristupa [M1] <br>
Kao što je detaljnije opisano kod prethodnog napada i ovde je potrebno voditi računa o podešavanjima kao sto su postavljanje Identity and Access Managment - IAM politika, Bucket-Level politika, postavljanje S3 Bucket Access Control Lists - ACL-ova. Bucket će biti podložan ovom napadu kada je Public i iz tog razloga ovo treba izbegavati. Međutim ukoliko postoji potreba da ipak bude javan, bitno je podesiti zaštitu na nivou samih objekata koje želimo da zaštitimo.

2. Upotreba neuobičajenih imena za bucket-e [M3]<br>
Upotrebom neuobičajenih i teško predvidivih imena može se povećati bezbednost i otežati neovlašćenim osobama da ih lako otkriju. Bitno je izbegavati ključne reči, brendove ili informacije o sadržaju prilikom izbora imena. Ako se koriste jasno definisana i predvidljiva imena napadači će ih mnogo lakše i brže identifikovati. Kada se koriste složeni nazivi mnogo je teže generisati takvo ime, a samim tim i pronaći bucket.

3. Enkripcija podataka [M2]<br>
Nakon što su pronadjeni javni bucket-i, napadač može da vidi podatke koji se nalaze u njima te ih je neophodno enkriptovati korišćenjem tehnika koje su opisane u prethodnom napadu.
 
### Bucket takeover [N3]

Napadač preuzima kontrolu nad nepravilno konfigurisanim Amazon S3 bucket-om koji je prethodno bio pod kontrolom legitimnog vlasnika.

Prvo je potrebno identifikovati bucket-e koji će biti meta napada. Budući da Bucket Enumeration predstavlja pronalazak javnih bucket-a upravo ovaj napad često predhodi Bucket Takeover napadu. Nakon identifikacije ciljnog bucket-a sledi proučavanje konfiguracije kao što su podešavanja IAM politika, Bucket-Level politika, S3 Bucket ACL-ova i drugih sa ciljem pronalska potencijalnih ranjivosti. Napadač zatim pokušava da preuzme kontrolu nad bucket-om kradjom autentifikacionih podataka, iskorišćavanjem ranjivosti ili pokušajem preuzimanja kontrole nad IAM ulogama koje imaju pristup bucket-u. Nakon preuzimanja bucket-a, ostvarena je pretnja 'Gubitak kontrole nad bucket-om' [P2]. Napadač nakon toga može da promeni konfiguracije bucket-a kako bi omogućio šire privilegije, dodao ili izbrisao IAM korisnike ili role, promenio Bucket-Level politike ili S3 Bucket ACL-ove u svoju korist. Ima mogućnost narušavanja integriteta podataka jer može da ih menja, briše ili dodaje nove. Može da izvršava druge napade kao što su Data Exfilitration ili Phishing napad dodavanjem zlonamernih objekata. 

#### Mitigacije 

1. Konfiguracija pristupa [M1]<br>
Kao i u pretnodna dva napada, konfiguracija pristupa igra ključnu ulogu kada je reč u prevencijama napada. <br><br>
2. Multifaktorska autentifikacija (MFA) [M4] <br>
Multifaktorska autentifikacija (MFA) je snažna bezbednosna praksa koja dodaje dodatni sloj autentifikacije kako bi se zaštitili korisnički nalozi i resursi, uključujući Amazon S3 bucket-ove. MFA za S3 resurse može se primeniti kako bi se otežao ili onemogućio neovlašćeni pristup, posebno nakon napada kao što je Bucket Takeover. Npr MFA se može postaviti pre nego što se korisniku dozvoli da menja neki resurs ili da ga briše. <br><br>
3. Enkripcija podataka [M2]<br>
Ukoliko je kontrola nad bucket-om već izgubljena dobro bi bilo da su podaci šifrovani, korišćenjem tehnika za šifrovanje koje su prethodno opisane, kako makar ne bi mogao da ih zloupotrebi.
   

### Reference
1. https://docs.aws.amazon.com/prescriptive-guidance/latest/strategy-aws-semicon-workloads/prevent-unauthorized-access.html
2. https://binaryguy.tech/aws/s3/iam-policies-vs-s3-policies-vs-s3-bucket-acls/  
3. https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html  
4. https://risk3sixty.com/2022/10/24/s3-buckets/
5. https://ieeexplore.ieee.org/document/9133399?denied
6. https://socradar.io/aws-s3-bucket-takeover-vulnerability-risks-consequences-and-detection/
   


