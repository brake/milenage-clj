(ns threegpp.milenage-test
  (:require [clojure.test :refer :all]
            [clojure.string :refer [upper-case]]
            [threegpp.milenage-clj :as ml]
            [threegpp.milenage-clj.biginteger :as big-int]
            [threegpp.milenage-test.hex :as hex]))


(defn- do-to-map [amap f]
  (reduce #(assoc %1 %2 (f (amap %2))) {} (keys amap)))

(defn- hexmap-to-intmap
  [m]
  (do-to-map m big-int/unhexlify))

(defn- hexmap-to-bytes
  [m]
  (do-to-map m hex/unhexlify))

(defn- print-buffer
  [label byte-val]
  (println (str label ": " (hex/hexlify-bytes byte-val) "  " (vec byte-val))))

;(def bigint-to-block @#'org.roganov.org.roganov.milenage_clj/bigint-to-block)
;(def aes-encrypt-int @#'org.roganov.org.roganov.milenage_clj/aes-encrypt-int)


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
          (mapv big-int/unhexlify
                ["465b5ce8b199b49faa5f0a2ee238a6bc"
                 "ee36f7cf037d37d3692f7f0399e7949a"
                 "9e2980c59739da67b136355e3cede6a2"])))

(def opc-test-data
  (zipmap [:k :op :op-c]
          (mapv upper-case ["465b5ce8b199b49faa5f0a2ee238a6bc"
                            "cdc202d5123e20f62b6d676ac72cb318"
                            "cd63cb71954a9f4e48a5994e37a02baf"])))

(def full-customization-test-data
  "Test data set with all constants (R and C) customized"
  {:test-data (let [test-data {:k "465b5ce8b199b49faa5f0a2ee238a6bc"
                               :rand "23553cbe9637a89d218ae64dae47bf35"
                               :op-c "cd63cb71954a9f4e48a5994e37a02baf"
                               :sqn "ff9bb4d0b607"
                               :amf "b9b9"
                               :f1 "4FEF17668A1B2BD1"
                               :f1* "1F7DB575C5BCC213"
                               :f2 "E62ED6A1D8BD9325"
                               :f3 "6B4C2FA2E83F66E0C8D6B44165D84B8D"
                               :f4 "C1B3127617EFC1F3A2A392B451AB9306"
                               :f5 "24E4BE006592"
                               :f5* "B1BF9AD8A2AE"
                               :autn "DB7F0AD0D395B9B94FEF17668A1B2BD1"}]
                   (do-to-map test-data upper-case))
   :c-const (let [c-const {:c1 "465b5ce8b199b49faa5f0a2ee238a6bc"
                           :c2 "407f3970f1e68def5bb987c1b981217d"
                           :c3 "4e82c626bf644bc9e4ddcc085d5ced75"
                           :c4 "00d75b6abfb310a35b6edcab063231de"
                           :c5 "2b10460594a356a6cfcd8a0dc9ffbbd3"}]
               (do-to-map c-const upper-case))
   :r-const {:r1 0x08
             :r2 0x13
             :r3 0x6A
             :r4 0x4A
             :r5 0x51}})

(deftest big-integer-conversion-test
  (testing "BigInteger <-> byte array test failed"
    (let [int-data (hexmap-to-intmap opc-test-data)
          bigint-val (int-data :k)
          hex-val (hex/hexlify-bigint bigint-val)]
      (is (= hex-val (opc-test-data :k))))))                  


;(deftest aes-int-test
;  (testing "AES result is incorrect"
;    (let [cipher (bigint/aes-encrypt (cipher-test-data :key) (cipher-test-data :plain))
;          plain (bigint/aes-decrypt (cipher-test-data :key) (cipher-test-data :cipher))]
;      (is (= (hex/hexlify-bigint plain) (hex/hexlify-bigint (cipher-test-data :plain))))
;      (is (= (hex/hexlify-bigint cipher) (hex/hexlify-bigint (cipher-test-data :cipher)))))))

(deftest opc-test
  (testing "OPc calculation is incorrect"
    (let [{:keys [k op]} (hexmap-to-bytes opc-test-data)
          opc (-> k
                  ml/create-rijndael-cipher
                  (ml/opc op)
                  hex/hexlify-bytes)]
      (is (= opc (opc-test-data :op-c))))))


(deftest etsits135207-test
  (testing "ETSI TS 135 207 test failed"
   (let [test-data (hexmap-to-bytes etsi-test-data)
         {:keys [k rand op-c sqn amf]} test-data
         cipher (ml/create-rijndael-cipher k)
         constants ml/sample-milenage-constants
         f1-res (ml/f1-all cipher rand op-c sqn amf constants)
         f1-hex (hex/hexlify-bytes (f1-res :f1))
         f1*-hex (hex/hexlify-bytes (f1-res :f1*))
         f2f5-res (ml/f2f5 cipher rand op-c constants)
         f2-hex (hex/hexlify-bytes (f2f5-res :f2))
         f5-hex (hex/hexlify-bytes (f2f5-res :f5))
         f3-hex (hex/hexlify-bytes (ml/f3 cipher rand op-c constants))
         f4-hex (hex/hexlify-bytes (ml/f4 cipher rand op-c constants))
         f5*-hex (hex/hexlify-bytes (ml/f5* cipher rand op-c constants))]

     (is (= f1-hex (etsi-test-data :f1)))
     (is (= f1*-hex (etsi-test-data :f1*)))
     (is (= f2-hex (etsi-test-data :f2)))
     (is (= f5-hex (etsi-test-data :f5)))
     (is (= f3-hex (etsi-test-data :f3)))
     (is (= f4-hex (etsi-test-data :f4)))
     (is (= f5*-hex (etsi-test-data :f5*))))))

(deftest milenage-customized-test
  (testing "Customized Milenage test failed"
    (let [test-data (:test-data full-customization-test-data)
          test-data-bytes (hexmap-to-bytes test-data)
          {:keys [k rand op-c sqn amf]} test-data-bytes
          cipher (ml/create-rijndael-cipher k)
          c-const (hexmap-to-bytes (:c-const full-customization-test-data))
          r-const (:r-const full-customization-test-data)
          constants (ml/milenage-constants c-const r-const)
          f1-res (ml/f1-all cipher rand op-c sqn amf constants)
          f1-hex (hex/hexlify-bytes (f1-res :f1))
          f1*-hex (hex/hexlify-bytes (f1-res :f1*))
          f2f5-res (ml/f2f5 cipher rand op-c constants)
          f2-hex (hex/hexlify-bytes (f2f5-res :f2))
          f5-hex (hex/hexlify-bytes (f2f5-res :f5))
          f3-hex (hex/hexlify-bytes (ml/f3 cipher rand op-c constants))
          f4-hex (hex/hexlify-bytes (ml/f4 cipher rand op-c constants))
          f5*-hex (hex/hexlify-bytes (ml/f5* cipher rand op-c constants))]
      (is (= f1-hex (test-data :f1)))
      (is (= f1*-hex (test-data :f1*)))
      (is (= f2-hex (test-data :f2)))
      (is (= f5-hex (test-data :f5)))
      (is (= f3-hex (test-data :f3)))
      (is (= f4-hex (test-data :f4)))
      (is (= f5*-hex (test-data :f5*))))))
