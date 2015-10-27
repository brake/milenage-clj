(ns org.roganov.milenage
  ^{:author "Constantin Roganov"}
  (:require [org.roganov.milenage.aes :as rijndael]
            [org.roganov.milenage.biginteger :as bigint]))

(def ^{:const true} ak-size 6)
(def ^{:private true :const true} half-block (/ rijndael/block-size-bytes 2))

(def r-const {:r1 64 :r2 0 :r3 32 :r4 64 :r5 96})

(def c-const {:c1 BigInteger/ZERO
              :c2 (BigInteger/valueOf 1)
              :c3 (BigInteger/valueOf 2)
              :c4 (BigInteger/valueOf 4)
              :c5 (BigInteger/valueOf 8)})

(defn- byte-array?
  [& args]
  (every? #(= (Class/forName "[B") (type %)) args))

(defn opc
  "Calculates OPc value from OP and K. Receives and returns BigIntegers.
  OPC = OP ⊕ E[OP]K"
  [k-bytes op-bytes]
  {:pre [(byte-array? k-bytes op-bytes)]}
  (let [[k op] (->> [k-bytes op-bytes]
                    (map byte-array)
                    (map bigint/from-bytes))]
    (->> op
         (bigint/aes-encrypt k)
         (bigint/xor op)
         bigint/to-byte-block)))

(defn- temp
  "Calculates TEMP value as defined in 3GPP TS 35.206 4.1
  TEMP = E[RAND ⊕ OPC]K"
  [^BigInteger k ^BigInteger rand ^BigInteger op-c]
  (->> op-c
       (bigint/xor rand)
       (bigint/aes-encrypt k)))

(defn- out1
  "Calculates OUT1 = E[TEMP ⊕ rot(IN1 ⊕ OPC, r1) ⊕ c1]K ⊕ OPC
  A 128-bit value IN1 is constructed as follows: 
    IN1[0] .. IN1[47] = SQN[0] .. SQN[47] 
    IN1[48] .. IN1[63] = AMF[0] .. AMF[15] 
    IN1[64] .. IN1[111] = SQN[0] .. SQN[47] 
    IN1[112] .. IN1[127] = AMF[0] .. AMF[15]"
  [^BigInteger tmp ^BigInteger op-c ^BigInteger k ^BigInteger in1]
  (-> op-c
      (bigint/xor in1)
      (bigint/left-circ-rotation (r-const :r1))
      (bigint/xor-all tmp (c-const :c1))
      (#(bigint/aes-encrypt k %))
      (bigint/xor op-c)))
        
(defn- out-n
  "Calculates OUTn = E[rot(TEMP⊕ OPC, rn) ⊕ cn]K ⊕ OPC"
  [^BigInteger tmp ^BigInteger op-c ^BigInteger k rn ^BigInteger cn]
  {:pre [(>= rn 0) (< rn rijndael/block-size-bits)]}
  (-> op-c
      (bigint/xor tmp)
      (bigint/left-circ-rotation rn)
      (bigint/xor cn)
      (#(bigint/aes-encrypt k %))
      (bigint/xor op-c)))

(defn- out2
  "Calculates OUT2 = E[rot(TEMP⊕ OPC, r2) ⊕ c2]K ⊕ OPC"
  [^BigInteger tmp ^BigInteger op-c ^BigInteger k]
  (let [c2 (c-const :c2)
        r2 (r-const :r2)]
    (out-n tmp op-c k r2 c2)))
  
(defn- out3
  "Calculates OUT3 = E[rot(TEMP⊕ OPC, r3) ⊕ c3]K ⊕ OPC"
  [^BigInteger tmp ^BigInteger op-c ^BigInteger k]
  (out-n tmp op-c k (r-const :r3) (c-const :c3)))

(defn- out4
  "Calculates OUT4 = E[rot(TEMP⊕ OPC, r4) ⊕ c4]K ⊕ OPC"
  [^BigInteger tmp ^BigInteger op-c ^BigInteger k]
  (out-n tmp op-c k (r-const :r4) (c-const :c4)))

(defn- out5
  "Calculates OUT5 = E[rot(TEMP⊕ OPC, r5) ⊕ c5]K ⊕ OPC"
  [^BigInteger tmp ^BigInteger op-c ^BigInteger k]
  (out-n tmp op-c k (r-const :r5) (c-const :c5)))

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

(defn f1-all
  "Executing f1 and f1* functions from Milenage framework.
   f1 = MAC-A, where MAC-A[0] .. MAC-A[63] = OUT1[0] .. OUT1[63]
   f1* = MAC-S, where MAC-S[0] .. MAC-S[63] = OUT1[64] .. OUT1[127]
   Returns hash map {:f1 f1-result :f1* f1*-result}"
  [k-bytes rand-bytes opc-bytes sqn-bytes amf-bytes]
  {:pre [(byte-array? k-bytes rand-bytes opc-bytes sqn-bytes amf-bytes)]}
  (let [[k rand op-c sqn amf] (map bigint/from-bytes
                                   [k-bytes rand-bytes opc-bytes sqn-bytes amf-bytes])
       in1-half (-> sqn
                    (.shiftLeft 16)
                    (.or amf))
       in1 (-> in1-half
               (.shiftLeft (/ rijndael/block-size-bits 2))
               (.or in1-half)
               bigint/ensure-unsigned)
       out1-bytes (-> (temp k rand op-c)
                      (out1 op-c k in1)
                      bigint/to-byte-block)
       f1 (byte-array (take half-block out1-bytes))
       f1* (byte-array (drop half-block out1-bytes))]
    {:f1 f1 :f1* f1*}))

(defn f2f5
  "Executing f2 and f5 functions from Milenage framework.
   f2 = RES, where RES[0] .. RES[63] = OUT2[64] .. OUT2[127]
   f5 = AK, where AK[0] .. AK[47] = OUT2[0] .. OUT2[47]
   Returns hash map {:f2 f2-result :f5 f5-result}."
  [k-bytes rand-bytes opc-bytes]
  {:pre [(byte-array? k-bytes rand-bytes opc-bytes)]}
  (let [[k rand op-c] (map bigint/from-bytes
                           [k-bytes rand-bytes opc-bytes])
        out2-bytes (-> (temp k rand op-c)
                       (out2 op-c k)
                       bigint/to-byte-block)
        f2 (byte-array (drop half-block out2-bytes))
        f5 (byte-array (take ak-size out2-bytes))]
    {:f2 f2 :f5 f5}))

(defn f3
  "Executing f3 function from Milenage framework
   f3 = CK, where CK[0] .. CK[127] = OUT3[0] .. OUT3[127]"
  [k-bytes rand-bytes opc-bytes]
  {:pre [(byte-array? k-bytes rand-bytes opc-bytes)]}
  (let [[k rand op-c] (map bigint/from-bytes
                           [k-bytes rand-bytes opc-bytes])]
    (-> (temp k rand op-c)
        (out3 op-c k)
        bigint/to-byte-block)))

(defn f4
  "Executing f4 function from Milenage framework
   f4 = IK, where IK[0] .. IK[127] = OUT4[0] .. OUT4[127]"
  [k-bytes rand-bytes opc-bytes]
  {:pre [(byte-array? k-bytes rand-bytes opc-bytes)]}
  (let [[k rand op-c] (map bigint/from-bytes
                           [k-bytes rand-bytes opc-bytes])]
    (-> (temp k rand op-c)
        (out4 op-c k)
        bigint/to-byte-block)))

(defn f5*
  "Executing f5* function from Milenage framework
   f5* = AK, where AK[0] .. AK[47] = OUT5[0] .. OUT5[47]"
  [k-bytes rand-bytes opc-bytes]
  {:pre [(byte-array? k-bytes rand-bytes opc-bytes)]}
  (let [[k rand op-c] (map bigint/from-bytes
                           [k-bytes rand-bytes opc-bytes])
        out5-bytes (-> (temp k rand op-c)
                       (out5 op-c k)
                       bigint/to-byte-block)]
    (byte-array (take ak-size out5-bytes))))