# Caddie - Enterprise sistem

## Uvod

Predmet analize je enterprise sistem po imenu Caddie. Caddie je sistem prvobitno namenjen za prikupljanje podataka od integrisanih aplikacija (GitHub, Slack itd). Prikupljeni podaci se analiziraju i prikazuju u vidu statistika. Prilikom GitHub integracije korisnik u Caddie aplikaciji moze imati pregled svih vrsta contribution-a i aktivnosti na nivou tima ili organizacije. Ukoliko je u pitanju Slack integracija, moguce je imati uvid u korisnikove aktivnosti u svim kanalima odredjene organizacije. Caddie takodje sadrzi kalendar i automatizovane izvestaje koje zaposleni mogu da popune svakog dana.

### Arhitektura

Arhitektura Caddie sistema je mikroservisno orijentisana. Zahtevi klijenta se prosledjuju direktno Caddie aplikaciji. Caddie komunicira se Github webhook i Slack webhook app preko Rabbit mq preko kog su aplikacije integrisane. Svaki od servisa ima zasebnu bazu podataka. Caddie aplikacija koristi PostgreSQL bazu, dok Github i Slack webhook aplikacije koristi Mongo bazu podataka. Sve tri aplikacije komuniciraju sa eksternim sistemima.

![](https://github.com/vulinana/ZOSS-Projekat/blob/main/DijagramiArhitektureSistema/2.%20nivo.png)

### Autentifikacija

Klijenti imaju mogucnost prijave na sistem koristeci Github ili Google OAuth. Takodje, moguca je autentifikacija samo putem mejl adrese i lozinke. Zahtev za autentifikaciju direktno se prosledjuje Caddie core aplikaciji. Autentifikacija je u potpunosti stateless i obavlja se koristeci jwt token.

### Autorizacija

U sistemu postoje dve uloge, administratorska i korisnicka. Svaki korisnik mora da pripada barem jednoj organizaciji. Akcenat je da korisnik odredjene organizacije ne sme da ima pristup niti uvid u podatke organizacije koje nije clan. Sto se tice autorizacije u organizaciji, implementirana je RBAC kontrola pristupa, sa rolama Owner, Administator i Member. Rola Member ima samo readonly pristup podacima, dok Administrator moze da menja podatke. Owner sadrzi sve permisije, a od Administratora se razlikuje po opciji brisanja organizacije. 


## Klijentska aplikacija

### Opis

Klijentska aplikacija Caddie sistema je spona izmedju korisnika i samog sistema. Omogucava integraciju Github i Slack eksternih sistema kako bi statistike postale dostupne korisniku na uvid. Takodje je korisniku dostupna mogucnost efikasne pretrage, kao i online placanja. Pored navedenog, korisniku su dostupne operacija nad kalendarom, upravljanje daily sastancima itd. Dostupna je i mogucnost komparacije korisnika, odnosno njihove efikasnosti u radu.

### Tehnologija 

Klijentska aplikacija implementirana je koristeci radni okvir React.js. Komunikacija sa sistemom obavlja se putem HTTPS protokola.


## Caddie core aplikacija

### Opis 

Caddie tj. sam core analiziranog sistema obavlja integraciju sa Slack i GitHub servisima preko Rabbitmq. Obradjuje dobijene podatke i vrsi analizu nad njima i dostavlja je klijentskoj aplikaciji u vidu statistika na nivou tima ili organizacije. Od eksternih sistema koristi pored Rabbitmq, AWS S3 file storage, Sendgrid servis za slanje mejlova, Redis servis za kesiranje i cron jobs, Fastforex servis za konverziju valuta kao i Stripe za online placanje. Takodje, za efikasnu pretragu u sistemu koristi se Algolia, eksterni servis koji se sa bazom Caddie servisa sinhronizuje preko Census ETL-a.

### Tehnologija

Caddie servis implementiran je koristeci Nest.js radni okvir. 


## GitHub webhook servis [2]

### Opis

Namena GitHub webhook servis namenjen je za integraciju sa GitHub eksternim servisom za dobavljanje podataka. Navedeni servis prima webhook zahteve koje mu dostavlja Github eksterni servis, a zatim GitHub webhook servis dobavlja detaljnije podatke slanjem Graphql zahteva ka eksternom servisu. Upakovani podaci se zatim salju do Caddie core aplikacije putem Rabbitmq reda cekanja. Webhook servis skladisti svoje podatke u zasebnu NoSQL bazu podataka, MongoDB.

## Tehnologija

Github webhook app implementirana je u radnom okviru Express.


## Slack Webhook servis [3]

### Opis

Slicno kao i u slucaju GitHub webhook servisa, i Slack webhook servis sluzi za dobavljanje podataka komunikacijom sa Slack eksternim servisom, koja je u ovom slucaju u oba smera http. Takodje ima svoju odvojenu bazu, MongoDB. Za razliku od Github webhook servisa, Slack servis mora da vodi racuna o skladistenju enkriptovanih korisnickih i bot tokena. 

### Tehnologija

Takodje je implementiran koristeci Express radni okvir.


## EKSTERNI SERVISI

## Stripe [7]

Integracijom u Caddie sistem nudi mogucnost online placanja. U slucaju analiziranog sistema, koristi se za placanje mesecne ili godisnje pretplate na koriscenje sistema. Komunikacija izmedju klijentske aplikacije i stripe sistema vrsi se preko Https protokola. Isto vazi i za komunikaciju izmedju Caddie servisa i Stripe-a.

## Fastforex

Koristi se kao eksterni servis za konverziju valuta u sistemu. Komunikacija se obavlja preko Http protokola.

## Redis [8]

Eksterni servis koristen u Caddie sistemu za kesiranje podataka i cron jobs. Komunikacija se obavlja preko Redis protokola - RESP.

## AWS S3 file storage [1]

Eksterni servis u oblaku koristen za skladistenje fajlova, u slucaju Caddie sistema primarno skladistenje slika. Komunikacija se obavlja putem Https protokola. 

## Sendgrid [5]

Eksterni servis cija je namena slanje mejlova korisnicima sistema. Komunikacija izmedju Caddie servisa i Sengrid-a obavlja se preko Https protokola. 

## Algolia [4]

Eksterni servis za pretragu za slucajeve koriscenja koji zahtevaju visokokvalitetno i relevantno pretrazivanje. Za njeno funkcionisanje neophodna je sinhronizacija sa PostgreSQL bazom Caddie servisa koja se obavlja upotrebom Census ETL. Komunikacija izmedju Caddie servisa i Algolia-e obavlja se putem Https protokola.

## Census ETL [6]

Eksterni servis namenjen za sinhronizaciju izmedju Caddie PostgreSQL baze podataka i Algolia-e. Omogucava automatsko dobavljanje novih podataka ili azuriranje vec postojecih iz Caddie baze podataka u Algolia-u.

## Rabbitmq

Servis namenjen za posredovanje poruka izmedju Caddie servisa i Github i Slack webhook servisa. Protokol koji koristi za komunikaciju je rmq.



## Nivo virtuelizacije, operativni sistem i hardver nece biti deo bezbednosne analize ovog sistema.


## Reference
1. https://medium.com/@anirban.pal.4341/upload-files-to-aws-s3-using-nestjs-and-multer-3e5b81f75ca6
2. https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/about-creating-github-apps
3. https://slack.dev/bolt-js/concepts
4. https://www.algolia.com/
5. https://docs.sendgrid.com/api-reference/how-to-use-the-sendgrid-v3-api/authentication
6. https://docs.getcensus.com/destinations/algolia
7. https://stripe.com/docs/billing/subscriptions/overview?fbclid=IwAR3WVMMFBmTCUih4f4sEHtPWidxgawJUdmQY2XjaLk2kI7DcsLrMjAgQfTM
8. https://redis.io/docs/












