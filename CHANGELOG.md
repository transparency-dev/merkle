# MERKLE changelog

## HEAD

* Breaking change: consistency proofs from `size1 = 0` to `size2 != 0` now always fail
  * Previously, this could succeed if the empty proof was provided
* Bump Go version from 1.19 to 1.20

## v0.0.2

* Fuzzing support
* Dependency updates, notably to go1.19

## v0.0.1

Initial release
