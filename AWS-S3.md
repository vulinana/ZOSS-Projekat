# AWS S3 eksterni servis

Amazon Simple Storage Service je usluga za skladištenje podataka u oblaku. Organizuje se u jedinstvene jedinice nazvane buckets. Bucket ima jedinstveno ime unutar AWS regije. Svaki bucket ima objekte, a objekat ima jedinstveni kljuc unutar bucket-a. Kljuc je putanja do objekta unutar bucket-a kao i njegov jedinstveni identifikator. Objekat je osnovna jedinica podatka koja se cuva.

## Napadi

### Data Exfilitration

Predstavlja neovlašćeni prenos ili krađu podataka koji su smešteni u S3 bucket-ovima. Napadač pokušava dobiti pristup osetljivim podacima koje se nalaze u bucket-ovima, pa ih preneti ili zloupotrebiti.

#### Pretnje

1. Gubitak osetljivih informacija
2. Neovlašćeni pristup osetljivim podacima

#### Mitigacije

1. Konfiguracija pristupa - potrebno je odrediti ko ima pristup kojim podacima i na koji način. Ovo podrazumeva razna podesavanja kao sto su postavljanje Identity and Access Managment - IAM politika (ograničavanje pristupa samo na određene radnje ili resurse), Bucket-Level dozvola (konfiguracija pristupa na nivou bucket-a), postavljanje Access Control Lists - ACL-ova (konfiguracija pristupa na nivou samih objekata).
2. Enkripcija podataka - enkripcija podatke čini nečitljivim, tako da su podaci napadaču postaju beskorisni bez odgovarajućeg ključa za dekripciju.
3. Rotacija pristupnih ključeva - predstavlja praksu redovne zamene ključeva. Smanjuje vremenski period tokom kog bi napadač mogao iskoristiti kompromitovani ključ.

### Bucket Enumeration

Napad koji podrazumeva otkrivanje postojanja S3 bucket-a i proveru da li su oni javni. Napadač koristi automatizovane alate ili skripte kako bi generisao moguća imena bucket-a (nasumične kombinacije ili koristeći rečnike sa često korišćenim imenima). Nakon toga proverava da li su oni javno dostupni. Najčešće se šalju HTTP zahtevi prema URL-u bucket-a i analizira se odgovor.


#### Pretnje

1. Neovlašćeni pristup osetljivim podacima
2. Otvaranje vrata drugim napadima - nakon što znamo da je bucket javno dostupan moguće je izvršiti napad kao što je Data Exfilitration koji je prethodno opisan, Bucket Enumeration koji će biti opisan ili druge napade.

#### Mitigacije

1. Konfiguracija pristupa 
2. Upotreba neuobičajenih imena za bucket-e - otežava napadačima pogadjanje imena.

### Bucket Takeover

Napadač preuzima kontrolu nad neaktivnim ili nepravilno konfigurisanim bucket-om koji je prethodno bio pod kontrolom legitimnog vlasnika. Prvo je potrebno identifikovati bucket-e koji će biti meta napda, nakon toga sledi proučavanje konfiguracije sa ciljem identifikacije slabosti koja će omogućiti neovlašćeni pristup. Zatim sledi kompromitiranje identiteta ili pristupnih ključeva.

#### Pretnje

1. Gubitak kontrole - napadač ima potpunu kontrolu nad bucket-om. Može da ih modifikuje, briše ili dodaje nove.
2. Neovlašćeni pristup osetljivim podacima koje može da zloupotrebi
3. Otvaranje vrata drugim napadima - moguće je izvesti Phishing napad postavljanjem lažnih web stranica u bucket-e. Ovo uključuje prevare korisnika da otkriju svoje osetljive podatke poput lozinki i podataka za plaćanje ili zlonamernih fajlova koji bi se proširili na druge delove sistema.

#### Mitigacije 

1. Konfiguracija pristupa
2. Propisna zaštita AWS ključeva

### Reference
Data Exfilitration<br>
1.https://www.shehackske.com/how-to/data-exfiltration-on-cloud-1606/
   
<br>Bucket Enumeration<br>
3. https://risk3sixty.com/2022/10/24/s3-buckets/
<br>4. https://ieeexplore.ieee.org/document/9133399?denied

<br>Bucket Takeover<br>
5. https://socradar.io/aws-s3-bucket-takeover-vulnerability-risks-consequences-and-detection/
   



