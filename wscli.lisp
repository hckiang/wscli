;;;; RFC 6455 WebSocket client

(defpackage :wscli
  (:use :cl :usocket)
  (:export
   #:websocket-connection
   #:connect
   #:connect-url
   #:close-connection
   #:wait-until-closed
   #:send-text
   #:send-binary
   #:send-ping
   #:run-message-loop
   #:conn-subprotocol
   #:conn-closed-p))

(in-package :wscli)

(defun make-websocket-key ()
  (let ((key (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (setf (aref key i) (ironclad:strong-random 256)))
    (cl-base64:usb8-array-to-base64-string key)))

(defun accept-key (client-key)
  (let* ((magic "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
         (combined (concatenate 'string client-key magic))
         (digest (ironclad:digest-sequence
                  :sha1
                  (ironclad:ascii-string-to-byte-array combined))))
    (cl-base64:usb8-array-to-base64-string digest)))

(defun mask-payload (payload mask)
  (let ((len (length payload))
        (result (make-array (length payload) :element-type '(unsigned-byte 8))))
    (dotimes (i len)
      (setf (aref result i)
            (logxor (aref payload i) (aref mask (mod i 4)))))
    result))

(defun read-exact (stream n)
  (let ((buf (make-array n :element-type '(unsigned-byte 8))))
    (loop for i from 0 below n
          do (setf (aref buf i) (read-byte stream)))
    buf))

(defun write-crlf (stream)
  (write-byte #x0d stream)
  (write-byte #x0a stream))

(defun write-ascii-line (stream string)
  (loop for c across string
        do (write-byte (char-code c) stream))
  (write-crlf stream))

(defun read-ascii-line (stream)
  (let ((bytes (make-array 0 :element-type '(unsigned-byte 8)
                             :adjustable t :fill-pointer 0)))
    (loop
      (let ((b (read-byte stream nil nil)))
        (cond
          ((null b)
           (return (if (zerop (length bytes))
                       nil
                       (babel:octets-to-string bytes :encoding :ascii))))
          ((= b #x0a)                   ; LF  (or the LF of a CRLF)
           (return (babel:octets-to-string bytes :encoding :ascii)))
          ((= b #x0d)                   ; CR
           (let ((next (read-byte stream nil nil)))
             (cond
               ((null next)             ; CR + EOF → treat as end
                (return (babel:octets-to-string bytes :encoding :ascii)))
               ((= next #x0a)           ; proper CRLF
                (return (babel:octets-to-string bytes :encoding :ascii)))
               (t                       ; bare CR → illegal
                (error "Bare CR in HTTP header line")))))
          (t
           (vector-push-extend b bytes)))))))

(defclass websocket-connection ()
  ((socket       :initarg :socket       :accessor conn-socket)
   (stream       :initarg :stream       :accessor conn-stream)
   (handler      :initarg :handler      :accessor conn-handler)
   (state        :initform :open        :accessor conn-state) ; :open | :closing | :closed
   (subprotocol  :initform nil          :accessor conn-subprotocol)
   (secure-p     :initform nil          :accessor conn-secure-p)
   (listener-thread :initform nil :accessor conn-listener-thread)
   (lock         :initform (bt:make-lock "ws-lock")
                 :accessor conn-lock)
   (closed-cv    :initform (bt:make-condition-variable)
                 :accessor conn-closed-cv)
   (close-timeout :initarg :close-timeout :initform 1.5
                  :accessor conn-close-timeout)))

(defun conn-closed-p (conn)
  (not (eq (conn-state conn) :open)))

(defun valid-close-status-p (code)
  (or (<= 1000 code 1003)
      (<= 1007 code 1014)          ; 1012–1014 are registered; harmless to accept
      (<= 3000 code 4999)))

(defun parse-http-status-line (line)
  (when (and line (>= (length line) 12)) ; "HTTP/1.x YYY"
    (let* ((sp1 (position #\Space line))
           (sp2 (and sp1 (position #\Space line :start (1+ sp1)))))
      (when (and sp1 sp2)
        (let ((version  (subseq line 0 sp1))
              (code-str (subseq line (1+ sp1) sp2))
              (reason   (subseq line (1+ sp2))))
          (when (and (>= (length version) 8)
                     (string= "HTTP/1." version :end2 7)
                     (= (length code-str) 3)
                     (every #'digit-char-p code-str))
            (values version (parse-integer code-str) reason)))))))

(defun perform-handshake (stream host path &key (origin nil) (protocols nil) (port 80) (secure nil))
  (let* ((key (make-websocket-key))
         (accept (accept-key key))
         (host-header
           (if (or (and (not secure) (= port 80))
                   (and secure (= port 443)))
               host
               (format nil "~A:~A" host port))))
    ;; Request line + headers
    (write-ascii-line stream (format nil "GET ~A HTTP/1.1" path))
    (write-ascii-line stream (format nil "Host: ~A" host-header))
    (write-ascii-line stream "Upgrade: websocket")
    (write-ascii-line stream "Connection: Upgrade")
    (write-ascii-line stream (format nil "Sec-WebSocket-Key: ~A" key))
    (write-ascii-line stream "Sec-WebSocket-Version: 13")
    (when origin
      (write-ascii-line stream (format nil "Origin: ~A" origin)))
    (when protocols
      (write-ascii-line stream
                        (format nil "Sec-WebSocket-Protocol: ~{~A~^, ~}" protocols)))
    (write-crlf stream)                 ; empty line
    (force-output stream)
    ;; Status line
    (let ((status (read-ascii-line stream)))
      (multiple-value-bind (version code reason)
          (parse-http-status-line status)
        (declare (ignore version reason))
        (unless (eql code 101)
          (error "WebSocket handshake failed: ~A" status))))
    ;; Headers
    (let ((got-accept nil)
          (got-upgrade nil)
          (got-connection nil)
          (negotiated-proto nil))
      (loop
        (let ((line (read-ascii-line stream)))
          (when (or (null line) (string= line ""))
            (return))
          (cond
            ((search "Sec-WebSocket-Accept:" line :test #'char-equal)
             (let ((val (string-trim '(#\Space #\Tab)
                                     (subseq line (1+ (position #\: line))))))
               (unless (string= val accept)
                 (error "Invalid Sec-WebSocket-Accept"))
               (setf got-accept t)))
            ((search "Upgrade:" line :test #'char-equal)
             (let ((val (string-trim '(#\Space #\Tab)
                                     (subseq line (1+ (position #\: line))))))
               (unless (string-equal val "websocket")
                 (error "Invalid Upgrade header: ~A" val))
               (setf got-upgrade t)))
            ((search "Connection:" line :test #'char-equal)
             (let ((val (string-trim '(#\Space #\Tab)
                                     (subseq line (1+ (position #\: line))))))
               ;; Connection may contain a comma-separated list of tokens.
               ;; We must find an ASCII case-insensitive match for "Upgrade".
               (when (loop with start = 0
                           for end = (position #\, val :start start)
                           for token = (string-trim '(#\Space #\Tab)
                                                    (subseq val start
                                                            (or end (length val))))
                           when (string-equal token "upgrade") return t
                             while end
                           do (setf start (1+ end)))
                 (setf got-connection t))))
            ((search "Sec-WebSocket-Protocol:" line :test #'char-equal)
             (setf negotiated-proto
                   (string-trim '(#\Space #\Tab)
                                (subseq line (1+ (position #\: line))))))
            ;; RFC 6455 §4.1: any extension not requested by the client is forbidden
            ((search "Sec-WebSocket-Extensions:" line :test #'char-equal)
             (let ((val (string-trim '(#\Space #\Tab)
                                     (subseq line (1+ (position #\: line))))))
               (unless (string= val "")
                 (error "Sec-WebSocket-Extensions present but no extensions were requested: ~A"
                        val)))))))
      (unless got-accept
        (error "Missing Sec-WebSocket-Accept header"))
      (unless got-upgrade
        (error "Missing or invalid Upgrade header"))
      (unless got-connection
        (error "Missing or invalid Connection header"))
      ;; RFC 6455 §4.1: negotiated subprotocol must have been offered by the client
      (when negotiated-proto
        (unless (and protocols
                     (member negotiated-proto protocols :test #'string=))
          (error "Invalid or unrequested Sec-WebSocket-Protocol: ~A"
                 negotiated-proto)))
      negotiated-proto)))


(defun write-frame (stream opcode payload &key (fin t) (mask t))
  (let* ((len (length payload))
         (mask-key (when mask
                     (let ((k (make-array 4 :element-type '(unsigned-byte 8))))
                       (dotimes (i 4) (setf (aref k i) (ironclad:strong-random 256)))
                       k)))
         (masked (if mask (mask-payload payload mask-key) payload))
         (b0 (logior (if fin #x80 0) (logand opcode #x0f)))
         (b1 (logior (if mask #x80 0)
                     (cond ((< len 126) len)
                           ((< len 65536) 126)
                           (t 127)))))
    ;; Control-frame constraints (RFC 6455 §5.5)
    (when (member opcode '(#x8 #x9 #xA))
      (when (> len 125)
        (error "Control frame payload too large (~D > 125)" len))
      (when (not fin)
        (error "Control frames must not be fragmented")))
    (write-byte b0 stream)
    (write-byte b1 stream)
    (cond
      ((= (logand b1 #x7f) 126)
       (write-byte (ldb (byte 8 8) len) stream)
       (write-byte (ldb (byte 8 0) len) stream))
      ((= (logand b1 #x7f) 127)
       (dotimes (i 8)
         (write-byte (ldb (byte 8 (* 8 (- 7 i))) len) stream))))
    (when mask
      (write-sequence mask-key stream))
    (write-sequence masked stream)
    (force-output stream)))

(defun write-frame-locked (conn opcode payload &key (fin t) (mask t))
  (bt:with-lock-held ((conn-lock conn))
    (let ((state (conn-state conn)))
      ;; Allow control frames (8,9,A) even while closing.
      (unless (or (eq state :open)
                  (and (eq state :closing) (member opcode '(#x8 #x9 #xA))))
        (error "Connection is closed")))
    (write-frame (conn-stream conn) opcode payload :fin fin :mask mask)))


(defun read-frame (stream)
  (let* ((b0 (read-byte stream))
         (b1 (read-byte stream))
         (fin (logbitp 7 b0))
         (rsv (logand b0 #x70))         ; RSV1|RSV2|RSV3
         (opcode (logand b0 #x0f))
         (masked (logbitp 7 b1))
         (len (logand b1 #x7f)))
    (when (plusp rsv)
      (error "RSV bits set (0x~X) but no extension negotiated" rsv))
    (when masked
      (error "Server sent a masked frame (MASK bit must be 0)"))
    (cond
      ((= len 126)
       (let ((extended (+ (ash (read-byte stream) 8)
                          (read-byte stream))))
         (when (< extended 126)
           (error "Non-minimal payload length encoding (126 used for ~D)"
                  extended))
         (setf len extended)))
      ((= len 127)
       (let ((extended 0)
             (first-byte nil))
         (dotimes (i 8)
           (let ((b (read-byte stream)))
             (when (zerop i)
               (setf first-byte b))
             (setf extended (+ (ash extended 8) b))))
         ;; Most-significant bit of the 64-bit length MUST be 0
         (when (logbitp 7 first-byte)
           (error "Payload length 64-bit value has MSB set"))
         (when (< extended 65536)
           (error "Non-minimal payload length encoding (127 used for ~D)"
                  extended))
         (setf len extended))))
    (let ((data (read-exact stream len)))
      (values opcode data fin))))


(defun connect (host port path
                &key (handler (lambda (type data) (declare (ignore type data))))
                  (background t)
                  (origin nil)
                  (protocols nil)
                  (secure nil)
                  (verify :required)
                  (hostname nil)) ; SNI hostname (defaults to HOST)
  (let* ((socket (socket-connect host port
                                 :element-type '(unsigned-byte 8)))
         (raw-stream (socket-stream socket))
         (stream (if secure
                     (cl+ssl:make-ssl-client-stream
                      raw-stream
                      :hostname (or hostname host)
                      :unwrap-stream-p t
                      :verify (or verify nil))
                     raw-stream))
         (proto (perform-handshake stream host path
                                   :origin origin
                                   :protocols protocols))
         (conn (make-instance 'websocket-connection
                              :socket socket
                              :stream stream
                              :handler handler)))
    (setf (conn-subprotocol conn) proto
          (conn-secure-p conn) secure)
    (when background
      (setf (conn-listener-thread conn)
            (bt:make-thread
             (lambda ()
               (run-message-loop conn))
             :name (format nil "ws-listener-~A:~A" host port))))
    conn))

(defun connect-url (url &rest args &key &allow-other-keys)
  (let* ((uri    (quri:uri url))
         (scheme (string-downcase (or (quri:uri-scheme uri) "")))
         (secure (cond ((string= scheme "wss") t)
                       ((string= scheme "ws")  nil)
                       (t (error "Unsupported scheme ~S in ~S (expected \"ws\" or \"wss\")"
                                 scheme url))))
         (host   (or (quri:uri-host uri)
                     (error "Missing host in URL ~S" url)))
         (port   (or (quri:uri-port uri)
                     (if secure 443 80)))
         (path   (let ((p (or (quri:uri-path uri) "/"))
                       (q (quri:uri-query uri)))
                   (if q
                       (concatenate 'string p "?" q)
                       p))))
    (apply #'connect host port path
           :secure secure
           args)))

(defun %try-finalize-close (conn)
  "Atomically transition :closing → :closed (or no-op if already closed).
   Returns T if *this* caller performed the transition (and is therefore
   responsible for closing the transport and invoking the user handler)."
  (bt:with-lock-held ((conn-lock conn))
    (unless (eq (conn-state conn) :closed)
      (setf (conn-state conn) :closed)
      (bt:condition-notify (conn-closed-cv conn)) ; also fixes the multi-waiter bug
      t)))

(defun arm-close-timeout (conn)
  (let ((timeout (conn-close-timeout conn)))
    (bt:make-thread
     (lambda ()
       (sleep timeout)
       (when (%try-finalize-close conn)          ; win the race?
         (ignore-errors
           (when (conn-secure-p conn)
             (close (conn-stream conn)))
           (socket-close (conn-socket conn)))
         ;; We won → we must deliver the callback (code 1006 = abnormal closure)
         (funcall (conn-handler conn) :close 1006)))
     :name "ws-close-timeout")))

(defun utf8-truncate (string max-bytes)
  "Return the longest prefix of STRING whose UTF-8 encoding
   is at most MAX-BYTES long.  The result is always valid UTF-8."
  (let ((byte-len 0)
        (end 0))
    (loop for i from 0 below (length string)
          for code = (char-code (char string i))
          for char-bytes = (cond ((< code #x80)    1)
                                 ((< code #x800)   2)
                                 ((< code #x10000) 3)
                                 (t                4))
          when (> (+ byte-len char-bytes) max-bytes)
            do (return)
          do (incf byte-len char-bytes)
             (setf end (1+ i)))
    (subseq string 0 end)))

(defun close-connection (conn &optional (code 1000) (reason ""))
  "Initiate the WebSocket closing handshake (non-blocking)."
  (bt:with-lock-held ((conn-lock conn))
    (when (eq (conn-state conn) :open)
      (unless (valid-close-status-p code)
        (setf code 1000))
      (let* ((reason (utf8-truncate reason 123))          ; ← character-safe
             (reason-bytes (babel:string-to-octets reason :encoding :utf-8))
             (payload (make-array (+ 2 (length reason-bytes))
                                  :element-type '(unsigned-byte 8))))
        (setf (aref payload 0) (ldb (byte 8 8) code)
              (aref payload 1) (ldb (byte 8 0) code))
        (replace payload reason-bytes :start1 2)
        (handler-case
            (write-frame (conn-stream conn) #x8 payload)
          (error ()))
        (setf (conn-state conn) :closing)
        (arm-close-timeout conn)))))

(defun wait-until-closed (conn &optional (timeout nil))
  "Block until the connection reaches :CLOSED.
   TIMEOUT is in seconds (NIL = wait forever).  Returns T on success,
   NIL on timeout."
  (bt:with-lock-held ((conn-lock conn))
    (loop
      (when (eq (conn-state conn) :closed)
        (return t))
      (unless (bt:condition-wait (conn-closed-cv conn)
                                 (conn-lock conn)
                                 :timeout timeout)
        (return nil)))))

(defun send-text (conn text)
  (when (conn-closed-p conn)
    (error "Connection is closed"))
  (write-frame-locked conn #x1
                      (babel:string-to-octets text :encoding :utf-8)))

(defun send-binary (conn data)
  (when (conn-closed-p conn)
    (error "Connection is closed"))
  (write-frame-locked conn #x2 data))

(defun send-ping (conn &optional (payload #()))
  (when (conn-closed-p conn)
    (error "Connection is closed"))
  (when (> (length payload) 125)
    (error "Ping payload too large (~D > 125 bytes)" (length payload)))
  (write-frame-locked conn #x9 payload))

(defun concatenate-byte-vectors (parts)
  (let* ((parts (nreverse parts))
         (total (loop for p in parts sum (length p)))
         (result (make-array total :element-type '(unsigned-byte 8)))
         (pos 0))
    (dolist (p parts)
      (replace result p :start1 pos)
      (incf pos (length p)))
    result))



(defun run-message-loop (conn)
  (let ((stream      (conn-stream conn))
        (handler     (conn-handler conn))
        (msg-opcode  nil)   ; 1 = text, 2 = binary, NIL = no message in progress
        (msg-parts   nil))  ; list of payload vectors (newest first)
    (labels ((deliver-message ()
               (let ((payload (concatenate-byte-vectors msg-parts)))
                 (if (= msg-opcode #x1)
                     ;; Strict UTF-8 for text frames (RFC 6455 §5.6)
                     (handler-case
                         (let ((text (babel:octets-to-string
                                      payload :encoding :utf-8 :errorp t)))
                           (funcall handler :text text)
                           (setf msg-opcode nil
                                 msg-parts  nil))
                       (babel-encodings:character-decoding-error ()
                         (close-connection conn 1007 "Invalid UTF-8")
                         (finish-close 1007)))
                     ;; Binary frames are opaque
                     (progn
                       (funcall handler :binary payload)
                       (setf msg-opcode nil
                             msg-parts  nil)))))
             (finish-close (code)
               (when (%try-finalize-close conn)
                 (ignore-errors
                  (when (conn-secure-p conn)
                    (close (conn-stream conn)))
                  (socket-close (conn-socket conn)))
                 (funcall handler :close code))
               (return-from run-message-loop)))
      (loop
        (when (eq (conn-state conn) :closed)
          (return))

        (multiple-value-bind (opcode payload fin)
            (handler-case (read-frame stream)
              (end-of-file ()
                (finish-close 1006))
              (error (e)
                (warn "Frame read error: ~A" e)
                (unless (conn-closed-p conn)
                  (close-connection conn 1002 "Protocol error"))
                (finish-close 1002)))

          (handler-case 
              (cond
                ((member opcode '(#x8 #x9 #xA))
                 (unless fin
                   (close-connection conn 1002 "Fragmented control frame")
                   (finish-close 1002)
                   )
                 (unless (<= (length payload) 125)
                   (close-connection conn 1002 "Control frame payload too large")
                   (finish-close 1002)
                   )
                 (case opcode
                   (#x8
                    (cond
                      ((= (length payload) 1)
                       (close-connection conn 1002 "Invalid close payload length")
                       (finish-close 1002))
                      (t
                       (let* ((code (if (zerop (length payload))
                                        1005
                                        (+ (ash (aref payload 0) 8)
                                           (aref payload 1))))
                              (reason-bytes (if (> (length payload) 2)
                                                (subseq payload 2)
                                                #())))
                         (when (plusp (length payload))
                           (unless (valid-close-status-p code)
                             (close-connection conn 1002 "Invalid close status code")
                             (finish-close 1002)))
                         (when (plusp (length reason-bytes))
                           (handler-case
                               (babel:octets-to-string reason-bytes :encoding :utf-8 :errorp t)
                             (babel-encodings:character-decoding-error ()
                               (close-connection conn 1007 "Invalid UTF-8 in close reason")
                               (finish-close 1007))))
                         ;; Reply (or no-op if we already sent a Close) then finish.
                         (close-connection conn (if (zerop (length payload)) 1000 code))
                         (finish-close code)))))
                   (#x9
                    (ignore-errors (write-frame-locked conn #xA payload))
                    (funcall handler :ping payload))
                   (#xA
                    (funcall handler :pong payload))))
                ((or (= opcode #x1) (= opcode #x2) (= opcode #x0))
                 (cond
                   ((null msg-opcode)
                    (when (= opcode #x0)
                      (close-connection conn 1002 "Unexpected continuation frame")
                      (finish-close 1002)
                      )
                    (setf msg-opcode opcode
                          msg-parts  (list payload))
                    (when fin
                      (deliver-message)))
                   (t
                    (unless (= opcode #x0)
                      (close-connection conn 1002 "Unexpected non-continuation frame during fragmented message")
                      (finish-close 1002)
                      )
                    (push payload msg-parts)
                    (when fin
                      (deliver-message)))))
                (t
                 (close-connection conn 1002 (format nil "Unknown opcode ~A" opcode))
                 (finish-close 1002)))
            (error (e)
              ;; If close-connection from other thread causes the state to flip from :open
              ;; to :closing or :closed, sending of message might signal. In this case
              ;; this handler catches that and it's an no-op. Otherwise if the state is still
              ;; :open, it's an unexpected error that needs warning and we close the connection
              ;; immediately.
              (unless (conn-closed-p conn)
                (warn "WebSocket listener error: ~A" e)
                (ignore-errors
                 (close-connection conn 1002 "Listener error")))
              (finish-close 1002))
            ))))))


;; Example usage
#|
(ql:quickload '(:usocket :cl+ssl :ironclad :cl-base64 :babel))

(defun my-handler (type data)
  (format t "~&[WS] ~A → ~S~%" type data))

(defparameter conn (connect "echo.websocket.org" 443 "/"
                     :secure t
                     :verify nil          ; set to :optional or t in production
                     :handler #'my-handler))
(send-text conn "Hello secure WebSocket!")

;;; Only use run-message-loop when :background is set to nil.
;; (run-message-loop conn)

(close-connection conn)

(defparameter conn (connect "stream.binance.com" 9443 "/stream?streams=btcusdt@trade"
                     :secure t
                     :verify nil          ; set to :optional or t in production
                     :handler #'my-handler))
(close-connection conn)
|#
