(ns threegpp.milenage-clj.biginteger
  ^{:author "Constantin Roganov"}
  (:require [threegpp.milenage-clj.rijndael :as rijndael])
  (:use [clojure.string :only [join]])
  (:import [java.math BigInteger]
           [javax.crypto Cipher]))

(def ^:const block-size-bytes 16)
(def ^:const block-size-bits (* block-size-bytes 8))

(def ^{:private true :const true} all-ones (->
                                 (repeat block-size-bytes "FF")
                                 join
                                 (BigInteger. 16)))

(defn ensure-unsigned
  "Turns the negative value of argument to positive one"
  [^BigInteger i & {:keys [bit-length] :or {bit-length block-size-bits}}]
  {:pre [(pos? bit-length)]}
  (if (neg? i)
    (-> BigInteger/ONE
        (.shiftLeft bit-length)
        (.add i))
    i))

(defn set-one-bit
  "Produces BigInteger with single bit n set"
  [n]
  {:pre [(>= n 0)]}
  (.setBit BigInteger/ZERO n))

(defn left-circ-rotation
  "Circular left bit rotation (Left bitwise rotating shift)"
  [^BigInteger i n]
  {:pre [(>= n 0)]}
  (if-not (zero? n)
    (let [^BigInteger i (ensure-unsigned i)
          sl (.shiftLeft i n)
          rev-shift (- block-size-bits n)
          sr (.shiftRight i rev-shift)
          comb-lr (.or sl sr)
          clean-result (.and comb-lr all-ones)]
      (ensure-unsigned clean-result))
    i))

(defn xor
  "Perform Exclusive OR (XOR) of arguments"
  [^BigInteger x ^BigInteger y]
  (apply (fn [^BigInteger n1 ^BigInteger n2]
           (.xor n1 n2))
         (map ensure-unsigned [x y])))

(defn xor-all
  "Exclusive OR of all BigInteger arguments"
  [& args]
  (reduce xor args))

(defn to-byte-block
  "Turns a BigInteger into array of bytes with size equivalent to required
  block size"
  [^BigInteger i & {:keys [block-size] :or {block-size block-size-bytes}}]
  {:pre [(pos? block-size)]}
  (let [^BigInteger i (ensure-unsigned i)
        ^bytes buf (.toByteArray i)               ; reflection (-> i ensure-unsigned .toByteArray)
        delta (->> buf alength (- block-size))]
    (cond
      (pos? delta)
        (->> buf
          (concat (byte-array delta))
          (byte-array block-size))
      (neg? delta)
      ; BigInteger.toByteArray adds extra zero byte to result so here we'll
      ; remove it.
        (->> buf
          (drop 1)
          (byte-array block-size))
      :else
        buf)))

(defn rijndael-encrypt
  "BigInteger to byte array wrapper for rijndael/ functions"
  [^Cipher cipher ^BigInteger plain]
  (->> plain
       to-byte-block
       ^bytes (rijndael/encrypt cipher)
       BigInteger.
       ensure-unsigned))

(defn unhexlify
  "Creates BigInteger from a hex string"
  [^String hs]
  (BigInteger. hs 16))

(defn from-bytes
  "Turns an array of bytes to BigIngeger"
  ; Only creating BigInteger from hex string is
  ; working properly.
  [bytes]
  (->> bytes
       (map (partial format "%02X"))
       (cons "00")
       (apply str)
       unhexlify))

;(defn hexlify
;  "Turns BinIngeger value into hex string (sometimes gives defferent result
;  than (.toString i 16))"
;  [^BigInteger i]
;  (-> i to-byte-block hex/hexlify))

;(defn print-as-hex
;  [^BigInteger i & {:keys [label] :or {label ""}}]
;  (->> i hexlify (str label) println))
;
;(defn print-full
;  [^BigInteger i & {:keys [label] :or {label "Value"}}]
;  (let [[bin hex dec] (map #(.toString i %) [2 16 10])
;        hex-upper (.toUpperCase hex)
;        hex-fine (hexlify i)]
;    (println label "==>")
;    (dorun (->>  [[bin hex-upper hex-fine dec]
;                  ["bin:" "hex:" "hex spec:" "dec:"]]
;             (map vector)  ;zip
;             (map #(apply println %))))
;    (println label "==<")))


