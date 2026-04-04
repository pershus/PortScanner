
#### Beskrivelse av appen 

Appen er designed slik at en bruker kan gjennomføre ett angrep, spesifikt et port scan angrep mot en annen maskin, brukeren vil få mulgiheten til å redigere ip addresser, port range og antall threads de vil bruke (in progress) 
Ved oppstart vil grensesnittet vises, hvor brukeren kan legge inn ønsket informasjon, deretter kjøres programmet mot offeret og resultatene lagres i en json fil for senere henting av data. Dersom ett angrep blir kjørt mot samme maskin under samme port range, vil ikke en ny scan kjøres da den gamle informasjonen vil bli benyttet. Dette åpner selvfølgelig for dårlig informasjon, noe som ikke er håndtert enda. Time stamp er lagt inn i json fila, slik at en i fremtiden, kan forkaste gammel informasjon. 
Enda ett aspekt som skal utbedres er multithreading, alt er lagt opp for bruken av det, men det mp enda implementeres. 

##### Diagramm
![Diagramm](image.png)

##### Spørsmål

1. Hvilke deler av pensum i emnet dekkes i prosjektet, og på hvilken måte? (For
eksempel bruk av arv, interface, delegering osv.)

Dette prosjektet dekker store deler av pensum, noe det kunne brukt mer er typisk innebygde klasser som f.eks. runnable iterable osv, derimot er nok den største "mangelen" arv. 

2. Dersom deler av pensum ikke er dekket i prosjektet deres, hvordan kunne dere brukt
disse delene av pensum i appen?

Arv er speielt den som kunne vært innteresant å benytte på en bedre måte, der den kunne vært brukt til å f.eks. redusere isolationen mellom hver klasse, og da heller benyttet scanner mer i både surface og depth

3. Hvordan forholder koden deres seg til Model-View-Controller-prinsippet? (Merk: det
er ikke nødvendig at koden er helt perfekt i forhold til Model-View-Controller
standarder. Det er mulig (og bra) å reflektere rundt svakheter i egen kode)

I henhold til MVC prinsippet har jeg vært ganske flink, hvor all dataprossering skjer en plass, all registrering skjer en annen plass og all GUI er en annen plass igjen, derimot kunne man ha flytta writePreviousResultToUser til f.eks. writer klassen hvor det kunne ha gitt litt mer mening.

5. Hvordan har dere gått frem når dere skulle teste appen deres, og hvorfor har dere
valgt de testene dere har? Har dere testet alle deler av koden? Hvis ikke, hvordan
har dere prioritert hvilke deler som testes og ikke? (Her er tanken at dere skal
reflektere rundt egen bruk av tester

Når jeg skulle teste applikasjonen min gikk jeg på å bitene indivudulet, der jeg følte at helheten kunne testes gjennom observasjon. Jeg har valgt å teste de delene jeg synes var mest hensiktsmessig å teste, dereav lagring og prosseringen av data. oppsettet på SYN packets, 3 way handshake og GUI er antatt godkjent, mtp. at det funker, og det kan observeres, om ønsket kan også SYN packets og 3 way handshake testes ganske greit med tcpdump. 
