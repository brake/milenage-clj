![Clojars Project](https://img.shields.io/clojars/v/threegpp.milenage-clj.svg) [![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

# threegpp.milenage-clj
  
A Clojure library designed to support [3GPP](http://www.3gpp.org)™ Milenage algorithm calculations according to 3GPP TS 35.206. 
## Features:
 
 * `OPc` calculation based on `OP` and `K`
 * `f1`-`f5` functions including `f1*` and `f5*`
 * Algorithm customization with `R` and `C` constants
 * You can use bundled [Rijndael](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) or any other instance of [javax.crypto.Cipher](https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html) 

## Usage

1. Create `cipher` [javax.crypto.Cipher](https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html), it will act as representation of a ciphering key `K`
  ```clojure
  (milenage-clj/create-rijndael-cipher k)
  ```

2. Create a MilenageConstants record with sample (AKA "default") or your own values.
  ```clojure
  milenage-clj/sample-milenage-constants  ; sample values
  (milenage-clj/milenage-constants c-const-map r-const-map)  ; your own values
  ```
  Where `c-const-map` is a map of byte arrays with keys `{:c1 :c2 :c3 :c4 :c5}` and `r-const-map` is a map with byte values and keys `{:r1 :r2 :r3 :r4 :r5}` 

3. Calculate `OPc` from `OP` and `cipher`
  ```clojure
  (milenage-clj/opc cipher op-bytes)
  ```
  
4. Call appropriate Milenage function:
  * `f2-all` -> `:f1`, `:f1*`
  * `f2f5` -> `:f2`, `:f5`
  * `f3`
  * `f4`
  * `f5*`

You can use [**test**](test/threegpp/milenage_test.clj#L135) module as an example of usage.

## Current Implementation details
Internally, for a bit arithmetic, module uses a [java.math.BigInteger](https://docs.oracle.com/javase/7/docs/api/java/math/BigInteger.html)

## License

Copyright © 2015-2016 Constantin Roganov

Distributed under the [MIT License](https://opensource.org/licenses/MIT).
