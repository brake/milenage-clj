(ns org.roganov.milenage-test
  (:require [clojure.test :refer :all]
            [clojure.string :refer [upper-case]]
            [org.roganov.milenage :as ml]
            [org.roganov.milenage.biginteger :as bigint]
            [org.roganov.hex :as hex]))


(defn- do-to-map [amap f]
  (reduce #(assoc %1 %2 (f (amap %2))) {} (keys amap)))

(defn- hexmap-to-intmap
  [m]
  (do-to-map m #(BigInteger. % 16)))

(defn- hexmap-to-bytes
  [m]
  (do-to-map m hex/unhexlify))

(defn- print-buffer
  [label byte-val]
  (println (str label ": " (hex/hexlify-bytes byte-val) "  " (vec byte-val))))

;(def bigint-to-block @#'org.roganov.milenage/bigint-to-block)
;(def aes-encrypt-int @#'org.roganov.milenage/aes-encrypt-int)


(def etsi-test-data 
  "Test set 1" 
  (let [test-data {:k "465b5ce8b199b49faa5f0a2ee238a6bc"
                   :rand "23553cbe9637a89d218ae64dae47bf35"
                   :op-c "cd63cb71954a9f4e48a5994e37a02baf"
                   :sqn "ff9bb4d0b607"
                   :amf "b9b9"
                   :f1 "4a9ffac354dfafb3"
                   :f1* "01cfaf9ec4e871e9"
                   :f2 "a54211d5e3ba50bf"
                   :f3 "b40ba9a3c58b2a05bbf0d987b21bf8cb"
                   :f4 "f769bcd751044604127672711c6d3441"
                   :f5 "aa689c648370"
                   :f5* "451e8beca43b"}]
    (do-to-map test-data upper-case)))

(def cipher-test-data 
  "K Plaintext Ciphertext" 
  (zipmap [:key :plain :cipher] 
          (mapv #(BigInteger. % 16) 
                ["465b5ce8b199b49faa5f0a2ee238a6bc"
                 "ee36f7cf037d37d3692f7f0399e7949a"
                 "9e2980c59739da67b136355e3cede6a2"])))

(def opc-test-data
  (zipmap [:k :op :op-c]
          (mapv upper-case ["465b5ce8b199b49faa5f0a2ee238a6bc"
                            "cdc202d5123e20f62b6d676ac72cb318"
                            "cd63cb71954a9f4e48a5994e37a02baf"])))


(deftest big-integer-conversion-test
  (testing "BigInteger <-> byte array test failed"
    (let [int-data (hexmap-to-intmap opc-test-data)
          bigint-val (int-data :k)
          hex-val (hex/hexlify-bigint bigint-val)]
      (is (= hex-val (opc-test-data :k))))))                  


(deftest aes-int-test
  (testing "AES result is incorrect"
    (let [cipher (bigint/aes-encrypt (cipher-test-data :key) (cipher-test-data :plain))
          plain (bigint/aes-decrypt (cipher-test-data :key) (cipher-test-data :cipher))]
      (is (= (hex/hexlify-bigint plain) (hex/hexlify-bigint (cipher-test-data :plain))))
      (is (= (hex/hexlify-bigint cipher) (hex/hexlify-bigint (cipher-test-data :cipher)))))))

(deftest opc-test
  (testing "OPc calculation is incorrect"
    (let [op-c (->> (hexmap-to-bytes opc-test-data)
                    ((juxt :k :op))
                    (apply ml/opc)
                    hex/hexlify-bytes)]
      (is (= op-c (opc-test-data :op-c))))))


(deftest etsits135207-test
  (testing "ETSI TS 135 207 test failed"
   (let [test-data (hexmap-to-bytes etsi-test-data)
         {:keys [k rand op-c sqn amf]} test-data
         f1-res (ml/f1-all k rand op-c sqn amf)
         f1-hex (hex/hexlify-bytes (f1-res :f1))
         f1*-hex (hex/hexlify-bytes (f1-res :f1*))
         f2f5-res (ml/f2f5 k rand op-c)
         f2-hex (hex/hexlify-bytes (f2f5-res :f2))
         f5-hex (hex/hexlify-bytes (f2f5-res :f5))
         f3-hex (hex/hexlify-bytes (ml/f3 k rand op-c))
         f4-hex (hex/hexlify-bytes (ml/f4 k rand op-c))
         f5*-hex (hex/hexlify-bytes (ml/f5* k rand op-c))]

     (is (= f1-hex (etsi-test-data :f1)))
     (is (= f1*-hex (etsi-test-data :f1*)))
     (is (= f2-hex (etsi-test-data :f2)))
     (is (= f5-hex (etsi-test-data :f5)))
     (is (= f3-hex (etsi-test-data :f3)))
     (is (= f4-hex (etsi-test-data :f4)))
     (is (= f5*-hex (etsi-test-data :f5*))))))
       
                              
    

