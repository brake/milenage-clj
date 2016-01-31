(ns
  ^{:author "Constantin Roganov"}
  threegpp.milenage-clj.rijndael
  (:import [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec]))

(defn- key-spec
  [raw-key]
  (SecretKeySpec. raw-key "AES"))

;(defn- create-aes-cipher
;  [^long direction ^SecretKeySpec spec]
;  (doto (Cipher/getInstance "AES/ECB/NoPadding")
;    (.init (int direction) spec)))
;
;(def encrypting-cipher (partial create-aes-cipher Cipher/ENCRYPT_MODE))
;
;(defn encrypt-ecb [rawkey bytes]
;  (let [spec (key-spec rawkey)]
;    (-> (encrypting-cipher spec)
;        (.doFinal bytes))))

(defn create-cipher [^bytes raw-key]
  ;; Reflection
  ;(doto (Cipher/getInstance "AES/ECB/NoPadding")
  ;  (.init Cipher/ENCRYPT_MODE
  ;         (-> raw-key
  ;             key-spec))))
  (do
    (let[^Cipher cipher (Cipher/getInstance "AES/ECB/NoPadding")
         ^SecretKeySpec kspec (key-spec raw-key)]
      (.init cipher Cipher/ENCRYPT_MODE kspec)
      cipher)))

(defn encrypt [^Cipher cipher bytes]
  (-> cipher
      (.doFinal bytes)))

