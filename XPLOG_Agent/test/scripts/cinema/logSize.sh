#!/bin/bash

# POST /api/bookings/
ab -n 1000 -T "application/json" -p scripts/cinema/addBooking.txt http://localhost/api/bookings/
# POST /api/movies/
ab -n 1000 -T "application/json" -p scripts/cinema/addMovie.txt http://localhost/api/movies/
# # POST /api/showtimes/
ab -n 1000 -T "application/json" -p scripts/cinema/addShowtime.txt http://localhost/api/showtimes/
# POST /api/users/
ab -n 1000 -T "application/json" -p scripts/cinema/addUser.txt http://localhost/api/users/
# GET /api/bookings/
ab -n 1000 -m GET http://localhost/api/bookings/
# GET /api/movies/
ab -n 1000 -m GET http://localhost/api/movies/
# GET /api/showtimes/
ab -n 1000 -m GET http://localhost/api/showtimes/
# GET /api/users/
ab -n 1000 -m GET http://localhost/api/users/

cd microservices-docker-go-mongodb
docker compose down
cd ..