(ns threegpp.milenage-test.hex
  (:require [threegpp.milenage-clj.biginteger :as bigint]))


(defn unhexlify
  "Convert a hex string to array of bytes"
  [^String s]
  (->> s
       (partition 2)
       (map (partial apply str))
       (map #(Integer/parseInt % 16))
       byte-array))

(defn hexlify-bytes
  "Convert binary data a hex string"
  [bytes]
  {:pre (= (type bytes) (Class/forName "[B"))}
  (->> bytes
       (map (partial format "%02X"))
       (apply str)))


(defn hexlify-bigint
  "Turns BinIngeger value into hex string (sometimes gives defferent result
  than (.toString i 16))"
  [^BigInteger i]
  (-> i bigint/to-byte-block hexlify-bytes))