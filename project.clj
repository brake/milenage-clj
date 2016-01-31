(defproject threegpp.milenage-clj "0.1.0"
  :description "3GPP TS 35.206 Milenage algorithm calculation (OPc and all functions)"
  :url "https://github.com/brake/milenage"
  :license {:name "MIT License"
            :url "https://opensource.org/licenses/MIT"}
  :dependencies [[org.clojure/clojure "1.7.0"]]
  :global-vars {*warn-on-reflection* true}
  :profiles {:uberjar {:aot :all}})
