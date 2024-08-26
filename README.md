# Blazor Auth With User Service

This is a Blazor web app that provides cookie, JWT and Api Key auth with a backing SQLite db.

## Background

This stores user and API key data in a single database. Have a look at the `UserDbContext`
in the `UserService` project, and you'll see the seed data so you can run this locally and login.

Currently, there are still some hard coded things like roles that will be cleaned up over time to 
make it simpler to modify.

## Author(s)

Frank Hale <frankhaledevelops@gmail.com>

## Date

25 August 2024
