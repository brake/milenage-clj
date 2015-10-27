(defproject org.roganov.milenage "0.1.0-SNAPSHOT"
  :description "3GPP TS 35.206 Milenage algorithm calculation (OPc and all functions)"
  :url "https://github.com/brake"
  :license {:name "MIT License"
            :url "https://opensource.org/licenses/MIT"}
  :dependencies [[org.clojure/clojure "1.7.0"]]
  :repositories {"local" ~(str (.toURI (java.io.File. "maven_repository")))}
  :profiles {:uberjar {:aot :all}})
