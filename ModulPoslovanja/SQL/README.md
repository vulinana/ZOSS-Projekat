# PostgreSQL
PostgreSQL, poznat i kao Postgres, predstavlja besplatan sistem za upravljanje relacionim bazama podataka koji pruža efikasno i pouzdano skladište podataka. 
Za PostgreSQL su karakteristične transakcije (sa svojim svojstvima atomičnosti, konzistentnosti, izolacije i izdržljivosti - ACID), automatski ažurirani prikazi, trigeri, strani ključevi i uskladištene procedure.
To je sistem otvorenog koda što znači da korisnici imaju pristup izvornom kodu i mogu da prilagođavaju softver sopstvenim potrebama. 
Poznat je i po svojoj proširivosti jer korisnici imaju mogućnost da kreiraju svoje tipove podataka, funkcije, operatore i jezike. 
Podržava napredne SQL upite, čime omogućava kompleksno modelovanje podataka i efikasno izvršavanje upita, kao i mogućnost replikacije podataka kako bi se povećali dostupnost i skalabilnost. <br>
Kao i svaki drugi softver tako je i PostgreSQL podložan sigurnosnim pretnjama <br>
1. Neovlašćena manipulacija podacima [P1]<br>
Ključni resurs koji je ugrožen u okviru PostgreSQL-a jesu sami podaci koji se u njemu skladište.
Napadač ima mogućnost manipulacije podacima i na taj način ugrožava njihovu poverljivost, integritet i dostupnost.
Na ovaj način može da nanese štetu pojedincu ili organizaciji radi sabotaže, da dođe do osetljivih podataka koje bi mogao da zloubotrebi, da vrši ucene ili iznude novca. <br>
2. Nedostupnost sistema [P2]<br>
U okviru ove pretnje ugroženi su baza podataka i server koji je odgovoran za obradu upita, transakcija i pružanje usluga korisnicima. Server je preopterećen, smanjena je dostupnost i onemogućeno je normalno funkcionisanje sistema.
Ostvarivanjem ove pretnje napadač ometa normalno poslovanje organizacije ili pojedinca onemogućavanjem pristupa bazi podataka što može dovesti do prekida rada aplikacija koje zavise od PostgreSQL-a.
Motivi mogu biti različiti kao što su npr želja da se nanese šteta konkurenciji ili protest usled neslaganja sa pojedincem/organizacijom.

## Napadi

### Stored Procedure Abuse [N1]

U PostgreSQL-u mogu postojati uskladištene procedure koje su napisane pomoću PostgreSQL proceduralnog jezika zvanog PL/PgSQL.
One često sadrze kompleksne logicke operacije izvršavane u samoj bazi podataka.
Uskladištene procedure omogućavaju ponovnu upotrebu koda (skup naredbi koji se često koriste se može grupisati u proceduru), optimizovati performanse (smanjuje se potreba za slanjem više upita iz aplikacije ka serveru).
Stored Procedure Abuse predstavlja napad koji se fokusira na zloupotrebu tih procedura. 

Prvi korak u ovom napadu jeste dobijanje pristupa nalozima ili aplikacijama koji imaju odgovarajuće dozvole za interakciju sa odgovarajućim procedurama.
Uobičajeni SQL serverski nalog koji je napadaču koristan je unapred izgrađeni administratorski nalog koji se podrazumevano zove System Administrator, ali svakako to može biti i bilo koji drugi koji ima odgovarajuće dozvole.
Jedna od najčešćih metoda za dobijanje pristupa administratorskom nalogu jeste pogađanje lozinke ili napad rečnikom. Administratori prečesto ne uspevaju da konfigurišu naloge sa jakim lozinkama.
Jednom kada napadač ima pristup nalogu koji ima odgovarajuće dozvole za rad sa procedurama on može da ih i iskoristi u svrhu napada. 

Postavlja se pitanje zašto napadači koriste uskladištene procedure za napade ako već imaju pristup nalogu sa visokim nivoom privilegija, kao što je System Administrator.
Poenta napada na stored procedure leži u tome što napadaču omogućava slobodnije kretanje i izvršavanje napada unutar same baze podataka i povezanih aplikacija, 
umesto da se ograniči na osnovne funkcionalnosti koje već ima kao administrator sistema. 
Uskladištene procedure mogu omogućiti napadaču da izvršava SQL upite i izaziva štetne efekte unutar same baze podataka. Ovaj napad se može koristiti u kombinaciji sa drugim napadima kao što je SQL Injection.
Na ovaj način se ostvaruje pretnja Neovlašćena manipulacija podacima [P1].

#### Mitigacije

1. Jaka autentifikacija [M1]<br>
Slabe lozinke na defaultnim nalozima su jedna od stvari za koje se napadači najčešće hvataju kada pokušavaju da dobiju pristup nalogu i zastrašujuće je koliko puta ovo funkcinoniše čak i u okruženjima koja bi navodno trebala da imaju visoku bezbednost.
Potreba za jakom autentifikacijom je važna bez obzira na tip naloga, ali je duplo važnija kada su u pitanju privilegovani nalozi koji imaju administrativna prava u okviru aplikacije. <br><br>
2. Sigurnosne konfiguracije [M2] <br>
Da bi se postigla dodatna zaštita potrebno je smanjiti površinu dobijanja pristupa nalogu. To se može postići eliminisanjem nepotrebnih resursa kao što su aplikacije koje nisu neophodne za rad SQL servera,
preimenovanjem, onemogućavanjem i/ili brisanjem nepotrebnih naloga. Neophodno je ograničiti privilegije korisničkim nalozima samo na ono što im je potrebno za obavljanje funkcija.<br><br>
3. Uklanjanje nepotrebnih uskladištenih procedura<br>
Ukoliko ne postoji neki specifičan razlog za koji nam trebaju uskladištene procedure, one se mogu u potpunosti ukloniti sa servera. Ukoliko su one ipak u nekim okolnostima neophodne, ali nije potrebno da uvek budu aktivne, treba ih onemogućiti.<br><br>
4. Evidencija, praćenje i upozoravanje<br>
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

Nakon što napadač uspe u privilegiranom eskalaciji, posledice mogu biti ozbiljne, jer mu mogu omogućiti neovlašćeni pregled podataka, izmenu ili brisanje podataka, dodavanje lažnih podataka. 
Na ovaj način napad Privilege Escalation ostvaruje pretnju 'Neovlašćena manipulacija podacima' [P1].

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
2. Obuka zaposlenih da prepoznaju Social Engineering [M6]<br>
Ljudi su obično najslabija karika u sigurnosti svake organizacije.
Oni mogu nesvesno doprineti napadu eskalacije koristeći slabe lozinke, klikćući na zlonamerne linkove ili priloge, i ignorišući upozorenja u vezi sa opasnim veb sajtovima.
Redovne obuke o bezbednosti osiguravaju da se nove pretnje mogu objasniti, kao i da u svesti zaposlenih održavaju bezbednosne politike.
Potrebno je naglasiti opasnosti i rizike deljenja naloga i akreditacija.



 
## Reference 
1. https://booksite.elsevier.com/samplechapters/9781597495516/02~Chapter_3.pdf
2. https://www.beyondtrust.com/blog/entry/privilege-escalation-attack-defense-explained
3. https://www.techtarget.com/searchsecurity/tip/6-ways-to-prevent-privilege-escalation-attacks
