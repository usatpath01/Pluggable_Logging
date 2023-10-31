#!/bin/bash

./scripts/cinema/calc.py <(cat ./cinema/benchmarking/bookings/all.txt | cut -d\  -f3 | sed 's/$/,/g' | tr -d '\n' | sed 's/,$//g')
echo
./scripts/cinema/calc.py <(cat ./cinema/benchmarking/bookings/insert.txt | cut -d\  -f3 | sed 's/$/,/g' | tr -d '\n' | sed 's/,$//g')
echo
./scripts/cinema/calc.py <(cat ./cinema/benchmarking/movies/all.txt | cut -d\  -f3 | sed 's/$/,/g' | tr -d '\n' | sed 's/,$//g')
echo
./scripts/cinema/calc.py <(cat ./cinema/benchmarking/movies/insert.txt | cut -d\  -f3 | sed 's/$/,/g' | tr -d '\n' | sed 's/,$//g')
echo
./scripts/cinema/calc.py <(cat ./cinema/benchmarking/showtimes/all.txt | cut -d\  -f3 | sed 's/$/,/g' | tr -d '\n' | sed 's/,$//g')
echo
./scripts/cinema/calc.py <(cat ./cinema/benchmarking/showtimes/insert.txt | cut -d\  -f3 | sed 's/$/,/g' | tr -d '\n' | sed 's/,$//g')
echo
./scripts/cinema/calc.py <(cat ./cinema/benchmarking/users/all.txt | cut -d\  -f3 | sed 's/$/,/g' | tr -d '\n' | sed 's/,$//g')
echo
./scripts/cinema/calc.py <(cat ./cinema/benchmarking/users/insert.txt | cut -d\  -f3 | sed 's/$/,/g' | tr -d '\n' | sed 's/,$//g')