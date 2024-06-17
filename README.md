# ZSONet

## zsonet
Testy powinny przechodzić, pomijając testy statystyk, które czasami przechodzą a czasami nie.

## transmitter
Nie wiedziałem zbytnio jaki ustawić maksymalny rozmiar kolejki w io\_uring\_init, więc zdecydowałem się na min z 
liczba połączeń plus stała, 16.
