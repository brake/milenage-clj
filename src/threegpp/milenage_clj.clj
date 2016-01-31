(ns threegpp.milenage-clj
  ^{:author "Constantin Roganov"}
  (:require [threegpp.milenage-clj.rijndael :as rijndael]
            [threegpp.milenage-clj.biginteger :as big-int])
  (:import [javax.crypto Cipher]))

(def ^:const block-size-bytes big-int/block-size-bytes)
(def ^:const block-size-bits (* block-size-bytes 8))

(def ^{:const true} ak-size 6)
(def ^{:private true :const true} half-block (/ block-size-bytes 2))

(def ^:const r-const {:r1 64 :r2 0 :r3 32 :r4 64 :r5 96})

(def ^:const c-const {:c1 BigInteger/ZERO
                      :c2 (BigInteger/valueOf 1)
                      :c3 (BigInteger/valueOf 2)
                      :c4 (BigInteger/valueOf 4)
                      :c5 (BigInteger/valueOf 8)})

(defn- do-to-map
  [amap f]
  (reduce-kv #(assoc %1 %2 (f %3)) {} amap))

(defn- byte-array?
  [& args]
  (every? #(= (Class/forName "[B") (type %)) args))

(defrecord MilenageConstants
  [^BigInteger c1 ^BigInteger c2 ^BigInteger c3 ^BigInteger c4 ^BigInteger c5
   r1 r2 r3 r4 r5])

(defn milenage-constants
  "Creates MilenageConstants record from two maps: c-const-bytes and r-const-ints.
  Bytes will be converted to BigIntegers."
  ([] (-> (merge c-const r-const)
          map->MilenageConstants))
  ([c-const-bytes r-const]
   (-> c-const-bytes
       (do-to-map big-int/from-bytes)
       (do-to-map big-int/ensure-unsigned)
       (merge r-const)
       map->MilenageConstants)))

(def sample-milenage-constants
  "Milenage constants defined as example in 3GPP TS 35.206 (4.1)"
  (milenage-constants))

(defprotocol MilenageCipher
  "128 bit block/key cipher for use inside of Milenage"
  (encrypt [this bytes] "Takes bytes and returns 128 bits encrypted output"))

(defrecord RijndaelCipher [^Cipher cipher]
  MilenageCipher
  (encrypt [_ bytes]
    (big-int/rijndael-encrypt cipher bytes)))

(defn create-rijndael-cipher
  "Creates RijndaelCipher from key defined as byte-array"
  [key-bytes]
  (-> key-bytes
      rijndael/create-cipher
      ->RijndaelCipher))

(defn- temp
  "Calculates TEMP value as defined in 3GPP TS 35.206 4.1
  TEMP = E[RAND ⊕ OPC]K"
  [cipher ^BigInteger op-c ^BigInteger rand]
  (->> op-c
       (big-int/xor rand)
       (encrypt cipher)))

(defn- out1
  "Calculates OUT1 = E[TEMP ⊕ rot(IN1 ⊕ OPC, r1) ⊕ c1]K ⊕ OPC
  A 128-bit value IN1 is constructed as follows: 
    IN1[0] .. IN1[47] = SQN[0] .. SQN[47] 
    IN1[48] .. IN1[63] = AMF[0] .. AMF[15] 
    IN1[64] .. IN1[111] = SQN[0] .. SQN[47] 
    IN1[112] .. IN1[127] = AMF[0] .. AMF[15]"
  [^BigInteger tmp cipher ^BigInteger op-c ^BigInteger in1 r1 ^BigInteger c1]
  (-> op-c
      (big-int/xor in1)
      (big-int/left-circ-rotation r1)
      (big-int/xor-all tmp c1)
      (#(encrypt cipher %))
      (big-int/xor op-c)))

(defn- out-n
  "Calculates OUTn = E[rot(TEMP⊕ OPC, rn) ⊕ cn]K ⊕ OPC"
  [^BigInteger tmp cipher ^BigInteger op-c rn ^BigInteger cn]
  {:pre [(>= rn 0) (< rn block-size-bits) (or (pos? rn) (zero? rn))]}
  (-> op-c
      (big-int/xor tmp)
      (big-int/left-circ-rotation rn)
      (big-int/xor cn)
      (#(encrypt cipher %))
      (big-int/xor op-c)))

(defn- out2
  "Calculates OUT2 = E[rot(TEMP⊕ OPC, r2) ⊕ c2]K ⊕ OPC"
  [^BigInteger tmp cipher ^BigInteger op-c ^MilenageConstants const]
  (out-n tmp cipher op-c (:r2 const) (:c2 const)))

(defn- out3
  "Calculates OUT3 = E[rot(TEMP⊕ OPC, r3) ⊕ c3]K ⊕ OPC"
  [^BigInteger tmp cipher ^BigInteger op-c ^MilenageConstants const]
  (out-n tmp cipher op-c (:r3 const) (:c3 const)))

(defn- out4
  "Calculates OUT4 = E[rot(TEMP⊕ OPC, r4) ⊕ c4]K ⊕ OPC"
  [^BigInteger tmp cipher ^BigInteger op-c ^MilenageConstants const]
  (out-n tmp cipher op-c (:r4 const) (:c4 const)))

(defn- out5
  "Calculates OUT5 = E[rot(TEMP⊕ OPC, r5) ⊕ c5]K ⊕ OPC"
  [^BigInteger tmp cipher ^BigInteger op-c ^MilenageConstants const]
  (out-n tmp cipher op-c (:r5 const) (:c5 const)))

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
  (-> i big-int/to-byte-block hexlify-bytes))

(defn f1-all
  "Executing f1 and f1* functions from Milenage framework.
   f1 = MAC-A, where MAC-A[0] .. MAC-A[63] = OUT1[0] .. OUT1[63]
   f1* = MAC-S, where MAC-S[0] .. MAC-S[63] = OUT1[64] .. OUT1[127]
   Returns hash map {:f1 f1-result :f1* f1*-result}"
  [cipher ^bytes rand ^bytes opc ^bytes sqn ^bytes amf ^MilenageConstants constants]
  {:pre [(byte-array? rand opc sqn amf)]}
  (let [[^BigInteger i-rand ^BigInteger i-op-c
         ^BigInteger i-sqn ^BigInteger i-amf] (map big-int/from-bytes
                                                   [rand opc sqn amf])
       in1-half (-> i-sqn
                    (.shiftLeft 16)
                    (.or i-amf))
       in1 (-> in1-half
               (.shiftLeft (/ block-size-bits 2))
               (.or in1-half)
               big-int/ensure-unsigned)
       out1-bytes (-> (temp cipher i-op-c i-rand)
                      (out1 cipher i-op-c in1 (:r1 constants) (:c1 constants))
                      big-int/to-byte-block)
       f1 (byte-array (take half-block out1-bytes))
       f1* (byte-array (drop half-block out1-bytes))]
    {:f1 f1 :f1* f1*}))

(defn f2f5
  "Executing f2 and f5 functions from Milenage framework.
   f2 = RES, where RES[0] .. RES[63] = OUT2[64] .. OUT2[127]
   f5 = AK, where AK[0] .. AK[47] = OUT2[0] .. OUT2[47]
   Returns hash map {:f2 f2-result :f5 f5-result}."
  [cipher rand-bytes opc-bytes ^MilenageConstants constants]
  {:pre [(byte-array? rand-bytes opc-bytes)]}
  (let [[rand op-c] (map big-int/from-bytes [rand-bytes opc-bytes])
        out2-bytes (-> (temp cipher op-c rand)
                       (out2 cipher op-c constants)
                       big-int/to-byte-block)
        f2 (byte-array (drop half-block out2-bytes))
        f5 (byte-array (take ak-size out2-bytes))]
    {:f2 f2 :f5 f5}))

(defn f3
  "Executing f3 function from Milenage framework
   f3 = CK, where CK[0] .. CK[127] = OUT3[0] .. OUT3[127]"
  [cipher rand-bytes opc-bytes ^MilenageConstants constants]
  {:pre [(byte-array? rand-bytes opc-bytes)]}
  (let [[rand op-c] (map big-int/from-bytes [rand-bytes opc-bytes])]
    (-> (temp cipher op-c rand)
        (out3 cipher op-c constants)
        big-int/to-byte-block)))

(defn f4
  "Executing f4 function from Milenage framework
   f4 = IK, where IK[0] .. IK[127] = OUT4[0] .. OUT4[127]"
  [cipher rand-bytes opc-bytes ^MilenageConstants constants]
  {:pre [(byte-array? rand-bytes opc-bytes)]}
  (let [[rand op-c] (map big-int/from-bytes [rand-bytes opc-bytes])]
    (-> (temp cipher op-c rand)
        (out4 cipher op-c constants)
        big-int/to-byte-block)))

(defn f5*
  "Executing f5* function from Milenage framework
   f5* = AK, where AK[0] .. AK[47] = OUT5[0] .. OUT5[47]"
  [cipher rand-bytes opc-bytes ^MilenageConstants constants]
  {:pre [(byte-array? rand-bytes opc-bytes)]}
  (let [[rand op-c] (map big-int/from-bytes [rand-bytes opc-bytes])
        out5-bytes (-> (temp cipher op-c rand)
                       (out5 cipher op-c constants)
                       big-int/to-byte-block)]
    (byte-array (take ak-size out5-bytes))))

(defn opc
  "Calculates OPc value from OP and MilenageCipher (which incorporates K).
  OPC = OP ⊕ E[OP]K"
  [cipher op-bytes]
  {:pre [(byte-array? op-bytes)]}
  (let [op (big-int/from-bytes op-bytes)]
    (->> op
         (encrypt cipher)
         (big-int/xor op)
         big-int/to-byte-block)))
