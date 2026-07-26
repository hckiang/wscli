(defsystem "wscli"
  :description "RFC 6455 WebSocket client TLS (cl+ssl)."
  :version "1.0.1"
  :author "Woodrow Hao Chi Kiang"
  :license "BSD-2-Clause"
  :depends-on ("usocket"
               "cl+ssl"
               "ironclad"
               "cl-base64"
               "quri"
               "babel"
               "bordeaux-threads")
  :serial t
  :components ((:file "wscli")))
