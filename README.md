# Readme.md
### Plik został dodany po zakończeniu zadania

Plik zawiera dodatkowy opis działania oraz minimalne wymagania dotyczące uruchomienia programu `main.rb`. 

## 1. Wymagania
Do uruchomienia programu wymagany jest zainstalowany i dodany do zmiennych środowiskowych język Ruby, oraz zainstalowane gemy:
> - csv - do odpowiedniego przetwarzania i parsowania pliku z logami.
> - time - do parsowania czau podanego w logach
> - uri i cgi do parsowania parametrów URL
> - levenshtein - do obliczania odległości Levenshteina nazw User-Agentów

## 2. Uruchomienie programu
Jeżeli wszystkie powyższe wymagania zostały spełnione wystarczy uruchomić program poleceniem `.\main.rb`. W konsoli powinny zostać wyświetlone pierwsze zapytania uznane za podjerzane, lub informacja o braku, któregoś z gemów. Skrypt domyślnie wyszukuje plik `logs.csv` znajdujący się w tym samym folderze. 

![0120-ezgif com-video-to-gif-converter](https://github.com/user-attachments/assets/e29b794c-64df-4efc-90c7-c2c2bb2b6291)

## 3. Opis działania
Program, po rozpoczęciu działania, ładuje do pamięci 100 pierwszych rekordów z logów, zakładając, że większość z nich to poprawne zapytania wykonane przez użytkowników, zapisując je w strukturze tablicy asocjacyjnej, w której kluczami są poszczególne adresy IP, zapamiętując 10 ostatnio dodanych adresów. Kolejno dodawane zapytania są przypisywane do zapamiętanych adresów. Jeżeli nowy adres spowoduje przekroczenie liczby `max_sessions`, najstarszy adres IP ze swoimi zapytaniami zostaje usunięty z tablicy, działając w architekturze `ring buffer`. Każde zapytanie, po zakończeniu "początkowego uczenia", jest poddawane ocenie w 3 kategoriach:

- **Nazwy User-Agenta**: Sprawdzane są poprzez obliczenie odległości Levenshteina względem wszystkich zapamiętanych w tablicy nazw przeglądarek. Następnie liczona jest średnia z ocen, gdzie każda ocena została uprzednio pomnożona przez liczbę wystąpień danej nazwy. W taki sposób częściej występujące nazwy przeglądarek mają większy wpływ na wynik. Empirycznie ustalono wartość 2.8 jako graniczną, poniżej której nazwy były uznawane za podejrzane.

- **Czas, który upłynął od wykonania ostatniego zapytania**: Za podejrzane zachowanie uznano wykonanie więcej niż 3 zapytań w tej samej sekundzie, ponieważ w logach jako 2 zapytania liczone było np. logowanie i przejście użytkownika na dashboard.

- **Podejrzane parametry**: Do ich wykrywania stworzono funkcję bazującą na wyrażeniach regularnych z najpopularniejszych ataków SQL Injection.

Jeżeli dowolne z kryteriów zostanie aktywowane, zapytanie i adres IP są zapisywane w tablicy asocjacyjnej z podejrzanymi adresami. Po zakończeniu działania program wypisuje ilość wykrytych podejrzanych zapytań w logach oraz eksportuje całość do pliku `output.txt`.
