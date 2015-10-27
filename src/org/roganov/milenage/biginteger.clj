(ns org.roganov.milenage.biginteger
  ^{:author "Constantin Roganov"}
  (:require ;[org.roganov.aes.hex :as hex]
            [org.roganov.milenage.aes :as aes128])
  (:use [clojure.string :only [join]])
  (:import [java.math BigInteger]))


(def ^{:private true :const true} all-ones (->
                                 (repeat aes128/block-size-bytes "FF")
                                 join
                                 (BigInteger. 16)))

(defn ensure-unsigned
  "Turns the negative value of argument to positive one"
  [^BigInteger i & {:keys [bit-length] :or {bit-length aes128/block-size-bits}}]
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

(def print-full nil)
(defn left-circ-rotation
  "Circular left bit rotation (Left bitwise rotating shift)"
  [^BigInteger i n]
  {:pre [(>= n 0)]}
  (if-not (zero? n)
    (let [i (ensure-unsigned i)
          sl (.shiftLeft i n)
          rev-shift (- aes128/block-size-bits n)
          sr (.shiftRight i rev-shift)
          comb-lr (.or sl sr)
          clean-result (.and comb-lr all-ones)]
      (ensure-unsigned clean-result))
    i))

(defn xor
  "Perform Exclusive OR (XOR) of arguments"
  [^BigInteger x ^BigInteger y]
  (apply #(.xor %1 %2) (map ensure-unsigned [x y])))

(defn xor-all
  "Exclusive OR of all BigInteger arguments"
  [& args]
  (reduce xor args))

(defn to-byte-block
  "Turns a BigInteger into array of bytes with size equivalent to required
  block size"
  [^BigInteger i & {:keys [block-size] :or {block-size aes128/block-size-bytes}}]
  {:pre [(pos? block-size)]}
  (let [buf (-> i ensure-unsigned .toByteArray)
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

(defn aes-encrypt
  "BigInteger to byte array wrapper for aes/ functions"
  [^BigInteger k ^BigInteger plain]
  (->> [k plain]
       (map to-byte-block)
       (apply aes128/encrypt-ecb)
       BigInteger.
       ensure-unsigned))

(defn aes-decrypt
  "BigInteger to byte array wrapper for aes/ functions"
  [^BigInteger k ^BigInteger cipher]
  (->> [k cipher]
       (map to-byte-block)
       (apply aes128/decrypt-ecb)
       BigInteger.
       ensure-unsigned))

(defn from-bytes
  "Turns an array of bytes to BigIngeger"
  ; Only creating BigInteger from hex string is
  ; working properly.
  [bytes]
  (->> bytes
       (map (partial format "%02X"))
       (cons "00")
       (apply str)
       (#(BigInteger. % 16))))

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


