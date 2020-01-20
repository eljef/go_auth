# Auth

Auth is a package that provides authentication and authorization
support. It provides hashing, password validation, and token
generation functionality.

## Project Maintenance

This project is maintained with standard golang utilities,
controlled via make. To see all Makefile targets, simply run
`make help` from the root source directory of the project.

## Packages

### Hash

The hash package provides functionality to hash data via the Argon2
hashing algorithms. Information on Argon2 can be found
[here](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04).

### Password

The password package provides policy matching functionality for
passwords.
