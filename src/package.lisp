(defpackage :wscli
  (:use :cl :usocket)
  (:export
   #:connect
   #:connect-url
   #:close-connection
   #:wait-until-closed
   #:send-text
   #:send-binary
   #:send-ping
   #:run-message-loop

   #:websocket-connection
   #:conn-socket
   #:conn-stream
   #:conn-handler
   #:conn-state
   #:conn-subprotocol
   #:conn-secure-p
   #:conn-listener-thread
   #:conn-lock
   #:conn-closed-cv
   #:conn-close-timeout
   #:conn-close-code
   #:conn-closed-p

   #:websocket-error
   #:websocket-error-message

   #:invalid-command-error
   #:handshake-error-message

   #:ping-payload-too-big-error
   #:ping-payload-too-big-error-n-bytes

   #:handshake-error

   #:handshake-http-error
   #:handshake-http-status-code
   #:handshake-http-response-line

   #:handshake-header-error
   #:handshake-header-name
   #:handshake-header-value
   #:handshake-header-expected

   #:handshake-extension-error
   #:handshake-extension-header

   #:handshake-subprotocol-error
   #:handshake-negotiated-protocol

   #:handshake-bare-cr-error

   #:handshake-url-error
   #:handshake-url-error-url
   #:handshake-url-error-reason

   #:protocol-error
   #:protocol-error-message
   #:protocol-error-close-code
   #:protocol-error-opcode

   #:reserved-bits-error
   #:reserved-bits-error-rsv-bits

   #:masked-frame-from-server-error

   #:non-minimal-payload-length-error
   #:non-minimal-payload-length-actual
   #:non-minimal-payload-length-declared

   #:payload-msb-set-error

   #:control-frame-too-large-error
   #:control-frame-too-large-error-size

   #:fragmented-control-frame-error

   #:invalid-close-payload-error

   #:invalid-close-code-error
   #:invalid-close-code-error-code

   #:invalid-utf8-error
   #:invalid-utf8-error-context
   #:invalid-utf8-error-octets

   #:unexpected-continuation-frame-error

   #:unexpected-data-frame-error
   #:unexpected-data-frame-opcode

   #:unknown-opcode-error
   #:unknown-opcode-error-opcode

   #:connection-closed-error))
