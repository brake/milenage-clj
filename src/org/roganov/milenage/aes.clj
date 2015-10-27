(ns
  ^{:author "Constantin Roganov"}
  org.roganov.milenage.aes
  (:import [javax.crypto KeyGenerator SecretKey Cipher]
           [javax.crypto.spec SecretKeySpec]))

(def block-size-bytes 16)
(def block-size-bits (* block-size-bytes 8))

(defn- key-spec
  [raw-key]
  (SecretKeySpec. raw-key "AES"))

(defn- create-aes-cipher
  [^long direction ^SecretKeySpec spec]
  (doto (Cipher/getInstance "AES/ECB/NoPadding")
    (.init (int direction) spec)))

(def encrypting-cipher (partial create-aes-cipher Cipher/ENCRYPT_MODE))
(def decrypting-cipher (partial create-aes-cipher Cipher/DECRYPT_MODE))

(defn gen-key [keygen]
  (-> keygen
      (.init block-size-bits)
      .generateKey
      .getEncoded))

(defn encrypt-ecb [rawkey bytes]
  (let [spec (key-spec rawkey)]
    (-> (encrypting-cipher spec)
        (.doFinal bytes))))

(defn decrypt-ecb [rawkey bytes]
  (let [spec (key-spec rawkey)]
    (-> (decrypting-cipher spec)
        (.doFinal bytes))))
