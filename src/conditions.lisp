(in-package :wscli)

(define-condition websocket-error (error)
  ((message :initarg :message :initform "" :reader websocket-error-message))
  (:report (lambda (c s) (format s "WebSocket error: ~A" (websocket-error-message c)))))

(define-condition invalid-command-error (websocket-error)
  ((message :initarg :message :initform "" :reader handshake-error-message))
  (:report (lambda (c s)
             (format s "WebSocket invalid command error: ~A"
                     (handshake-error-message c)))))

(define-condition handshake-error (websocket-error)
  ((message :initarg :message :initform "" :reader handshake-error-message))
  (:report (lambda (c s)
             (format s "WebSocket handshake error: ~A"
                     (handshake-error-message c)))))

(define-condition protocol-error (websocket-error)
  ((message    :initarg :message    :initform "" :reader protocol-error-message)
   (close-code :initarg :close-code :reader protocol-error-close-code :initform 1002)
   (opcode     :initarg :opcode     :reader protocol-error-opcode     :initform nil))
  (:report (lambda (c s)
             (format s "WebSocket protocol error (close code ~D): ~A"
                     (protocol-error-close-code c)
                     (protocol-error-message c)))))

(define-condition connection-closed-error (websocket-error) ())

;; ------------

(define-condition ping-payload-too-big-error (invalid-command-error)
  ((n-bytes :initarg n-bytes :reader ping-payload-too-big-error-n-bytes))
  (:report (lambda (c s)
             (format s "Ping payload too big (at most 125 bytes, but wanted to send ~D bytes)"
                     (ping-payload-too-big-error-n-bytes c)))))

(define-condition handshake-http-error (handshake-error)
  ((status-code :initarg :status-code :reader handshake-http-status-code)
   (response-line :initarg :response-line :reader handshake-http-response-line))
  (:report (lambda (c s)
             (format s "WebSocket handshake failed: ~A (HTTP ~D)"
                     (handshake-http-response-line c)
                     (handshake-http-status-code c)))))

(define-condition handshake-header-error (handshake-error)
  ((header-name :initarg :header-name :reader handshake-header-name)
   (received-value :initarg :received-value :reader handshake-header-value :initform nil)
   (expected-value :initarg :expected-value :reader handshake-header-expected :initform nil))
  (:report (lambda (c s)
             (format s "WebSocket handshake error in header ~A: "
                     (handshake-header-name c))
             (if (handshake-header-expected c)
                 (format s "expected ~S, got ~S"
                         (handshake-header-expected c)
                         (handshake-header-value c))
                 (format s "invalid or missing value ~@[~S~]"
                         (handshake-header-value c))))))

(define-condition handshake-extension-error (handshake-error)
  ((extension-header :initarg :extension-header :reader handshake-extension-header))
  (:report (lambda (c s)
             (format s "WebSocket handshake error: server sent unsolicited extension: ~A"
                     (handshake-extension-header c)))))

(define-condition handshake-subprotocol-error (handshake-error)
  ((negotiated-protocol :initarg :negotiated-protocol :reader handshake-negotiated-protocol))
  (:report (lambda (c s)
             (format s "WebSocket handshake error: server selected unrequested subprotocol: ~S"
                     (handshake-negotiated-protocol c)))))

(define-condition handshake-bare-cr-error (handshake-error)
  ()
  (:report (lambda (c s)
             (declare (ignore c))
             (format s "WebSocket handshake error: bare CR in HTTP header line"))))

(define-condition handshake-url-error (handshake-error)
  ((url :initarg :url :reader handshake-url-error-url)
   (reason :initarg :reason :reader handshake-url-error-reason))
  (:report (lambda (c s)
             (format s "WebSocket URL error for ~S: ~A"
                     (handshake-url-error-url c)
                     (handshake-url-error-reason c)))))

(define-condition reserved-bits-error (protocol-error)
  ((rsv-bits :initarg :rsv-bits :reader reserved-bits-error-rsv-bits))
  (:default-initargs :close-code 1002
                     :message "RSV bits set")
  (:report (lambda (c s)
             (format s "WebSocket protocol error: RSV bits set (0x~X) but no extension negotiated"
                     (reserved-bits-error-rsv-bits c)))))

(define-condition masked-frame-from-server-error (protocol-error)
  ()
  (:default-initargs :close-code 1002
                     :message "Server sent a masked frame")
  (:report (lambda (c s)
             (declare (ignore c))
             (format s "WebSocket protocol error: server sent a masked frame"))))

(define-condition non-minimal-payload-length-error (protocol-error)
  ((actual-length :initarg :actual-length :reader non-minimal-payload-length-actual)
   (declared-length :initarg :declared-length :reader non-minimal-payload-length-declared))
  (:default-initargs :close-code 1002
                     :message "Non-minimal payload length encoding")
  (:report (lambda (c s)
             (format s "WebSocket protocol error: non-minimal payload length encoding (~D used for ~D)"
                     (non-minimal-payload-length-declared c)
                     (non-minimal-payload-length-actual c)))))

(define-condition payload-msb-set-error (protocol-error)
  ()
  (:default-initargs :close-code 1002
                     :message "Payload length 64-bit value has MSB set")
  (:report (lambda (c s)
             (declare (ignore c))
             (format s "WebSocket protocol error: payload length 64-bit value has MSB set"))))


(define-condition control-frame-too-large-error (protocol-error)
  ((size :initarg :size :reader control-frame-too-large-error-size))
  (:default-initargs :close-code 1002
                     :message "Control frame payload too large")
  (:report (lambda (c s)
             (format s "WebSocket protocol error: control frame payload too large (~D > 125)"
                     (control-frame-too-large-error-size c)))))

(define-condition fragmented-control-frame-error (protocol-error)
  ()
  (:default-initargs :close-code 1002
                     :message "Fragmented control frame")
  (:report (lambda (c s)
             (declare (ignore c))
             (format s "WebSocket protocol error: fragmented control frame"))))

(define-condition invalid-close-payload-error (protocol-error)
  ()
  (:default-initargs :close-code 1002
                     :message "Invalid close payload length")
  (:report (lambda (c s)
             (declare (ignore c))
             (format s "WebSocket protocol error: close frame payload has invalid length (1 byte)"))))

(define-condition invalid-close-code-error (protocol-error)
  ((received-code :initarg :received-code :reader invalid-close-code-error-code))
  (:default-initargs :close-code 1002
                     :message "Invalid close status code")
  (:report (lambda (c s)
             (format s "WebSocket protocol error: invalid close status code ~D"
                     (invalid-close-code-error-code c)))))

(define-condition invalid-utf8-error (protocol-error)
  ((context :initarg :context :reader invalid-utf8-error-context)  ;; :text or :close-reason
   (octets  :initarg :octets  :reader invalid-utf8-error-octets   ;; optional raw bytes
            :initform nil))
  (:default-initargs :close-code 1007
                     :message "Invalid UTF-8")
  (:report (lambda (c s)
             (format s "WebSocket protocol error: invalid UTF-8 in ~A"
                     (invalid-utf8-error-context c)))))

(define-condition unexpected-continuation-frame-error (protocol-error)
  ()
  (:default-initargs :close-code 1002
                     :message "Unexpected continuation frame")
  (:report (lambda (c s)
             (declare (ignore c))
             (format s "WebSocket protocol error: unexpected continuation frame"))))

(define-condition unexpected-data-frame-error (protocol-error)
  ((received-opcode :initarg :received-opcode :reader unexpected-data-frame-opcode))
  (:default-initargs :close-code 1002
                     :message "Unexpected non-continuation frame during fragmented message")
  (:report (lambda (c s)
             (format s "WebSocket protocol error: unexpected non-continuation frame (~D) during fragmented message"
                     (unexpected-data-frame-opcode c)))))

(define-condition frame-too-large-error (protocol-error)
  ((size :initarg :size :reader frame-too-large-error-size))
  (:default-initargs :close-code 1009
                     :message "Message too big")
  (:report (lambda (c s)
             (format s "WebSocket protocol error: the peer advertised too large (~D bytes) a frame" 
                     (frame-too-large-error-size c)))))

(define-condition unknown-opcode-error (protocol-error)
  ((opcode :initarg :opcode :reader unknown-opcode-error-opcode))
  (:default-initargs :close-code 1002
                     :message "Unknown opcode")
  (:report (lambda (c s)
             (format s "WebSocket protocol error: unknown opcode ~D"
                     (unknown-opcode-error-opcode c)))))


