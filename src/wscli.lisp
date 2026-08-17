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
  (declare (type (simple-array (unsigned-byte 8) (*)) payload mask)
           (optimize (speed 3) (safety 0) (debug 0)))
  (let* ((len (length payload))
         (result (make-array len :element-type '(unsigned-byte 8))))
    (declare (type fixnum len)
             (type (simple-array (unsigned-byte 8) (*)) result))
    (dotimes (i len)
      (declare (type fixnum i))
      (setf (aref result i)
            (logxor (aref payload i) (aref mask (mod i 4)))))
    result))

(defun read-exact (stream n)
  (declare (type stream stream)
           (type (unsigned-byte 63) n)
           (optimize (speed 3) (safety 1)))
  ;; [GC KILLER]: Shouldn't.
  (let ((buf (make-array n :element-type '(unsigned-byte 8)))
        (start 0))
    (declare (type (simple-array (unsigned-byte 8) (*)) buf)
             (type fixnum start))
    (loop
      (when (= start n) (return buf))
      (let ((count (read-sequence buf stream :start start :end n)))
        (declare (type fixnum count))
        (when (zerop count)
          (error 'end-of-file :stream stream))
        (incf start count)))))

(defun write-crlf (stream)
  (declare (type stream stream)
           (optimize (speed 3) (safety 1)))
  (write-byte #x0d stream)
  (write-byte #x0a stream))

(defun write-ascii-line (stream string)
  (declare (type stream stream)
           (type string string)
           (optimize (speed 3) (safety 1)))
  (loop for c across string
        do (write-byte (char-code c) stream))
  (write-crlf stream))

(defun read-ascii-line (stream)
  (declare (type stream stream)
           (optimize (speed 3) (safety 1)))
  (let ((bytes (make-array 0 :element-type '(unsigned-byte 8)
                             :adjustable t :fill-pointer 0)))
    (declare (type (array (unsigned-byte 8) (*)) bytes))
    (loop
      (let ((b (read-byte stream nil nil)))
        (cond
          ((null b)
           (return (if (zerop (length bytes))
                       nil
                       (babel:octets-to-string bytes :encoding :ascii))))
          ((= b #x0a)
           (return (babel:octets-to-string bytes :encoding :ascii)))
          ((= b #x0d)
           (let ((next (read-byte stream nil nil)))
             (cond
               ((null next)
                (return (babel:octets-to-string bytes :encoding :ascii)))
               ((= next #x0a)
                (return (babel:octets-to-string bytes :encoding :ascii)))
               (t
                ;; HTTP/1.1 receivers are allowed to accept bare LF for robustness (RFC 7230 §3.5)
                (error 'handshake-bare-cr-error)))))
          (t
           (vector-push-extend b bytes)))))))

(defclass websocket-connection ()
  ((socket       :initarg :socket       :accessor conn-socket)
   (stream       :initarg :stream       :accessor conn-stream)
   (handler      :initarg :handler      :accessor conn-handler)
   (state        :initform :open        :accessor conn-state) ; :open | :closing | :closed
   (subprotocol  :initform nil          :accessor conn-subprotocol)
   (secure-p     :initform nil          :accessor conn-secure-p)
   (max-frame-size :initarg :max-frame-size
                   :initform (* 100 1024 1024)
                   :accessor conn-max-frame-size
                   :type (integer 0 #.most-positive-fixnum))
   (reuse-text-message-strbuf :initarg :reuse-text-message-strbuf
                              :initform nil
                              :accessor reuse-text-message-strbuf)
   (listener-thread :initform nil :accessor conn-listener-thread)
   (lock         :initform (bt:make-recursive-lock "ws-lock")
                 :accessor conn-lock)
   (closed-cv    :initform (bt:make-condition-variable)
                 :accessor conn-closed-cv)
   (close-timeout :initarg :close-timeout :initform 1.5
                  :accessor conn-close-timeout)
   (close-code   :initform 1006 :accessor conn-close-code)
   (close-reason :initform "" :accessor conn-close-reason)))

(defun conn-closed-p (conn)
  (declare (type websocket-connection conn)
           (optimize (speed 3) (safety 1)))
  (bt:with-recursive-lock-held ((conn-lock conn))
    (not (eq (conn-state conn) :open))))

(defun valid-close-status-p (code)
  (declare (type integer code))
  (or (<= 1000 code 1003)
      (<= 1007 code 1014)  ; 1012–1014 are in for example RFC 8441; harmless to accept
      (<= 3000 code 4999)))

(defun parse-http-status-line (line)
  (declare (type (or null simple-string) line))
  (when (and line (>= (length line) 12)) ; "HTTP/1.x YYY" because §4.1: "... HTTP version MUST be at least 1.1."
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

(defun perform-handshake (stream host path
                          &key
                            (origin nil)
                            (protocols nil)
                            (port 80)
                            (secure nil)
                            (extra-headers nil))
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
    (dolist (hdr extra-headers)
      (destructuring-bind (name . value) hdr
        (write-ascii-line stream (format nil "~A: ~A" name value))))
    (write-crlf stream)                 ; empty line
    (finish-output stream)
    ;; Status line
    (let ((status (read-ascii-line stream)))
      (multiple-value-bind (version code reason)
          (parse-http-status-line status)
        (declare (ignore version reason))
        (unless (eql code 101)
          (error 'handshake-http-error :status-code code :response-line status))))
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
                 (error 'handshake-header-error
                        :header-name "Sec-WebSocket-Accept"
                        :received-value val
                        :expected-value accept))
               (setf got-accept t)))
            ((search "Upgrade:" line :test #'char-equal)
             (let ((val (string-trim '(#\Space #\Tab)
                                     (subseq line (1+ (position #\: line))))))
               (unless (string-equal val "websocket")
                 (error 'handshake-header-error
                        :header-name "Upgrade"
                        :received-value val
                        :expected-value "websocket"))
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
                 (error 'handshake-extension-error :extension-header val)))))))
      (unless got-accept
        (error 'handshake-header-error :header-name "Sec-WebSocket-Accept"))
      (unless got-upgrade
        (error 'handshake-header-error :header-name "Upgrade"))
      (unless got-connection
        (error 'handshake-header-error :header-name "Connection"))
      ;; RFC 6455 §4.1: negotiated subprotocol must have been offered by the client
      (when negotiated-proto
        (unless (and protocols
                     (member negotiated-proto protocols :test #'string=))
          (error 'handshake-subprotocol-error :negotiated-protocol negotiated-proto)))
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
        (error 'control-frame-too-large-error :size len :message "Control frame payload too large"))
      (when (not fin)
        (error 'fragmented-control-frame-error :message "Control frames must not be fragmented")))
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
    (finish-output stream)))

(defun write-frame-locked (conn opcode payload &key (fin t) (mask t))
  (bt:with-recursive-lock-held ((conn-lock conn))
    (let ((state (conn-state conn)))
      ;; Allow control frames (8,9,A) even while closing.
      (unless (or (eq state :open)
                  (and (eq state :closing) (member opcode '(#x8 #x9 #xA))))
        (error 'connection-closed-error)))
    (write-frame (conn-stream conn) opcode payload :fin fin :mask mask)))



(declaim (ftype (function (stream (integer 0 #.most-positive-fixnum))
                          (values (unsigned-byte 4)
                                  (simple-array (unsigned-byte 8) (*))
                                  boolean))
                read-frame))
(defun read-frame (stream max-frame-size)
  (declare (type stream stream)
           (type (integer 0 #.most-positive-fixnum) max-frame-size)
           (optimize (speed 3) (safety 1)))
  (let* ((b0 (the (unsigned-byte 8) (read-byte stream)))
         (b1 (the (unsigned-byte 8) (read-byte stream)))
         (fin (logbitp 7 b0))
         (rsv (logand b0 #x70))
         (opcode (logand b0 #x0f))
         (masked (logbitp 7 b1))
         (len (logand b1 #x7f)))
    (declare (type (unsigned-byte 8) b0 b1)
             (type boolean fin masked)
             (type (unsigned-byte 4) opcode)
             (type (unsigned-byte 7) rsv)
             (type (integer 0 127) len))
    (when (plusp rsv)
      (error 'reserved-bits-error :rsv-bits rsv))
    (when masked
      (error 'masked-frame-from-server-error))
    (let ((payload-len
           (cond
             ((= len 126)
              (let ((extended (+ (ash (the (unsigned-byte 8) (read-byte stream)) 8)
                                 (the (unsigned-byte 8) (read-byte stream)))))
                (declare (type (unsigned-byte 16) extended))
                (when (< extended 126)
                  (error 'non-minimal-payload-length-error
                         :actual-length extended
                         :declared-length 126))
                extended))
             ((= len 127)
              (let ((lenbuf (read-exact stream 8)))
                (declare (type (simple-array (unsigned-byte 8) (8)) lenbuf))
                (let ((extended 0)
                      (first-byte (aref lenbuf 0)))
                  (declare (type (unsigned-byte 64) extended)
                           (type (unsigned-byte 8) first-byte))
                  (dotimes (i 8)
                    (declare (type fixnum i))
                    (setf extended (+ (ash extended 8) (aref lenbuf i))))
                  (when (logbitp 7 first-byte)
                    (error 'payload-msb-set-error))
                  (when (< extended 65536)
                    (error 'non-minimal-payload-length-error
                           :actual-length extended
                           :declared-length 127))
                  extended)))
             (t len))))
      (declare (type (integer 0 #.most-positive-fixnum) payload-len))
      (when (>= payload-len max-frame-size)
        (error 'frame-too-large-error :size payload-len))
      (let ((data (read-exact stream payload-len)))
        (values opcode data fin)))))


(defun connect (host port path
                &key (handler (lambda (type data) (declare (ignore type data))))
                  (background t)
                  (origin nil)
                  (protocols nil)
                  (secure nil)
                  (verify :required)
                  (hostname nil)     ; SNI hostname (defaults to HOST)
                  (max-frame-size (* 100 1024 1024))
                  (extra-headers nil)
                  (reuse-text-message-strbuf nil))
  (declare (type (integer 0 *) max-frame-size))
  (when (> max-frame-size #.most-positive-fixnum)
    (error 'max-frame-size-too-big-error :n max-frame-size))
  (locally
      (declare (type (integer 0 #.most-positive-fixnum) max-frame-size))
    (let* ((socket (socket-connect host port
                                   :element-type '(unsigned-byte 8)))
           (raw-stream (socket-stream socket))
           (stream (if secure
                       (cl+ssl:make-ssl-client-stream
                        raw-stream
                        :hostname (or hostname host)
                        ;; :unwrap-stream-p t is supposedly more direct and faster, but it causes
                        ;; FreeBSD Clozure CL to fail with corrupt memory inside the SSL library
                        ;; for unknown reasons, especially under heavy load.
                        ;;
                        ;; Interestingly, fukamachi's websocket-driver fails the exact same way
                        ;; on the same machine (they use :unwrap-stream-p t), so I believe this is
                        ;; not a wscli bug per-se. For safety reasons, we use Lisp stream here.
                        ;;
                        ;; With Lisp streams, I haven't seen any memory corruptions under very heavy
                        ;; load across multiple machines and both SBCL and CCL.
                        :unwrap-stream-p nil
                        :verify (or verify nil))
                       raw-stream))
           (proto (perform-handshake stream host path
                                     :origin origin
                                     :protocols protocols
                                     :extra-headers extra-headers))
           (conn (make-instance 'websocket-connection
                                :socket socket
                                :stream stream
                                :handler handler
                                :max-frame-size max-frame-size
                                :reuse-text-message-strbuf reuse-text-message-strbuf)))
      (setf (conn-subprotocol conn) proto
            (conn-secure-p conn) secure)
      (when background
        (setf (conn-listener-thread conn)
              (bt:make-thread
               (lambda ()
                 (run-message-loop conn))
               :name (format nil "ws-listener-~A:~A" host port))))
      conn)))

(defun connect-url (url &rest args &key &allow-other-keys)
  (declare (type string url))
  (let* ((uri      (quri:uri url))
         (scheme   (string-downcase (or (quri:uri-scheme uri) "")))
         (secure   (cond ((string= scheme "wss") t)
                         ((string= scheme "ws")  nil)
                         (t
                          (error 'handshake-url-error
                                 :url url
                                 :reason (format nil "Unsupported scheme ~S in ~S (expected \"ws\" or \"wss\")"
                                                 scheme url)))))
         (raw-host (or (quri:uri-host uri)
                       (error 'handshake-url-error
                              :url url
                              :reason (format nil "Missing host in URL ~S" url))))
         ;; quri keeps brackets on IPv6 literals; most socket / SNI APIs want them stripped
         (host     (if (and (stringp raw-host)
                            (> (length raw-host) 1)
                            (char= (char raw-host 0) #\[)
                            (char= (char raw-host (1- (length raw-host))) #\]))
                       (subseq raw-host 1 (1- (length raw-host)))
                       raw-host))
         (port     (or (quri:uri-port uri)
                       (if secure 443 80)))
         (path     (let ((p (or (quri:uri-path uri) "/"))
                         (q (quri:uri-query uri)))
                     (if q
                         (concatenate 'string p "?" q)
                         p)))
         (fragment (quri:uri-fragment uri)))
    ;; RFC 6455 / common practice: fragment is meaningless and should be rejected
    (when fragment
      (error 'handshake-url-error
             :url url
             :reason (format nil "Fragment identifier ~S is not allowed in WebSocket URL ~S"
                             fragment url)))
    ;; Detect conflicting :secure supplied by the caller
    (let ((provided (getf args :secure 'missing)))
      (unless (eq provided 'missing)
        (let ((provided-bool (and provided t))) ; any non-nil → t
          (unless (eq provided-bool secure)
            (error 'handshake-url-error
                   :url url
                   :reason (format nil ":secure ~S conflicts with scheme ~S (implies ~S)"
                                   provided scheme secure))))))
    ;; Strip :secure so the scheme-derived value always wins cleanly
    ;; (avoids duplicate-keyword subtleties and silent overriding)
    (let ((clean-args
            (loop for (k v) on args by #'cddr
                  unless (eq k :secure)
                    collect k and collect v)))
      (apply #'connect host port path
             :secure secure
             clean-args))))

(defun %try-finalize-close (conn &optional (code 1006) (reason ""))
  (bt:with-recursive-lock-held ((conn-lock conn))
    (unless (eq (conn-state conn) :closed)
      (setf (conn-state conn) :closed
            (conn-close-code conn) code
            (conn-close-reason conn) reason)
      (bt:condition-notify (conn-closed-cv conn))
      t)))

(defun arm-close-timeout (conn)
  (let ((timeout (conn-close-timeout conn)))
    (bt:make-thread
     (lambda ()
       (sleep timeout)
       ;; Only set the state + unblock the reader.
       ;; NEVER close the stream/socket from this thread.
       (when (%try-finalize-close conn 1006)
         (ignore-errors
           (socket-shutdown (conn-socket conn) :input))))
     :name "ws-close-timeout")))


(defun utf8-truncate (string max-bytes)
  (declare (type string string)
           (type integer max-bytes))
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
  (declare (type integer code)
           (type string reason))
  (bt:with-recursive-lock-held ((conn-lock conn))
    (when (eq (conn-state conn) :open)
      (unless (valid-close-status-p code)
        (setf code 1000))
      (let* ((reason (utf8-truncate reason 123))
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
  (bt:with-recursive-lock-held ((conn-lock conn))
    (loop
      (when (eq (conn-state conn) :closed)
        (return t))
      (unless (bt:condition-wait (conn-closed-cv conn)
                                 (conn-lock conn)
                                 :timeout timeout)
        (return nil)))))

(defun send-text (conn text)
  (declare (type websocket-connection conn)
           (type string text)
           (optimize (speed 3) (safety 1)))
  (when (conn-closed-p conn)
    (error 'connection-closed-error))
  (write-frame-locked conn #x1
                      (babel:string-to-octets text :encoding :utf-8)))

(defun send-binary (conn data)
  (declare (type websocket-connection conn)
           (type (array (unsigned-byte 8) (*)) data)
           (optimize (speed 3) (safety 1)))
  (when (conn-closed-p conn)
    (error 'connection-closed-error))
  (write-frame-locked conn #x2 data))

(defun send-ping (conn
                  &optional
                    (payload #.(make-array 0 :element-type '(unsigned-byte 8))))
  (declare (type websocket-connection conn)
           (type (array (unsigned-byte 8) (*)) payload)
           (optimize (speed 3) (safety 1)))
  (when (conn-closed-p conn)
    (error 'connection-closed-error))
  (when (> (length payload) 125)
    (error 'ping-payload-too-big-error :n-bytes (length payload)))
  (write-frame-locked conn #x9 payload))

(defun %ensure-char-buffer (buffer needed)
  (declare (type (or null string) buffer)
           (type (integer 0 #.most-positive-fixnum) needed)
           (optimize (speed 3) (safety 1)))
  (cond ((null buffer)
         (make-array (max needed 4096)
                     :element-type 'character
                     :fill-pointer 0
                     :adjustable t))
        ((>= (array-total-size buffer) needed)
         buffer)
        (t
         (adjust-array buffer
                       (max needed (the fixnum (* 2 (array-total-size buffer))))
                       :fill-pointer (fill-pointer buffer)))))

(defun %utf8-decode-borrowed (octets buffer &key (start 0) end)
  (declare (type (array (unsigned-byte 8) (*)) octets)
           (type (integer 0 #.most-positive-fixnum) start)
           (type (or null (integer 0 #.most-positive-fixnum)) end)
           (optimize (speed 3) (safety 1)))
  (let* ((end    (or end (length octets)))
         (needed (the fixnum (- end start)))
         (buf    (%ensure-char-buffer buffer needed)))
    (declare (type fixnum needed)
             (type string buf))
    (let ((n-written (reckless-utf8:utf8-decode-into octets buf
                                                     :start start
                                                     :end end
                                                     :dest-start 0)))
      (setf (fill-pointer buf) (+ 0 n-written))
      buf)))

(defun run-message-loop (conn)
  (declare (type websocket-connection conn)
           (optimize (speed 3) (safety 1)))
  (let ((stream      (conn-stream conn))
        (handler     (conn-handler conn))
        (max-frame-size (conn-max-frame-size conn))
        (msg-opcode  nil)   ; 1 = text, 2 = binary, NIL = no message in progress
        (msg-buffer  nil)   ; adjustable (unsigned-byte 8) vector or NIL
        (msg-len     0)
        (text-buf    (if (reuse-text-message-strbuf conn)
                         (make-array 4096
                                     :element-type 'character
                                     :fill-pointer 0
                                     :adjustable t)
                         nil)))
    (declare (type stream stream)
             (type function handler)
             (type (integer 0 #.most-positive-fixnum) max-frame-size)
             (type (or null (unsigned-byte 4)) msg-opcode)
             (type (or null (array (unsigned-byte 8) (*))) msg-buffer)
             (type fixnum msg-len))
    (labels ((deliver-payload (opcode payload)
               (declare (type (unsigned-byte 4) opcode)
                        (type (array (unsigned-byte 8) (*)) payload))
               (if (= opcode #x1)
                   (if (reuse-text-message-strbuf conn)
                       (handler-case
                           (progn
                             (setf text-buf (%utf8-decode-borrowed payload text-buf))
                             (funcall handler :text text-buf))
                         (reckless-utf8:utf8-decoding-error (e)
                           (funcall handler :error e)
                           (close-connection conn 1007 "Invalid UTF-8")
                           (finish-close 1007 "Invalid UTF-8")))
                       (handler-case
                           ;; ALLOCATES...
                           (let ((text (babel:octets-to-string payload :encoding :utf-8 :errorp t)))
                             (funcall handler :text text))
                         (babel-encodings:character-decoding-error (e)
                           (funcall handler :error e)
                           (close-connection conn 1007 "Invalid UTF-8")
                           (finish-close 1007 "Invalid UTF-8"))))
                   (funcall handler :binary payload)))
             (deliver-message ()
               (let ((payload (if (zerop msg-len)
                                  (make-array 0 :element-type '(unsigned-byte 8))
                                  (subseq msg-buffer 0 msg-len)))) ;ALLOCATES.
                 (declare (type (simple-array (unsigned-byte 8) (*)) payload))
                 (deliver-payload msg-opcode payload)
                 (setf msg-opcode nil
                       msg-buffer nil
                       msg-len    0)))
             (finish-close (code &optional (reason ""))
               (declare (type (integer 0 *) code)
                        (type string reason))
               (%try-finalize-close conn code reason)
               (return-from run-message-loop)))
      (unwind-protect
           (loop
             (bt:with-recursive-lock-held ((conn-lock conn))
               (when (eq (conn-state conn) :closed)
                 (return)))
             (multiple-value-bind (opcode payload fin)
                 (handler-case (read-frame stream max-frame-size)
                   (end-of-file ()
                     (finish-close 1006 "End of file"))
                   (frame-too-large-error (c)
                     (funcall handler :error c)
                     (close-connection conn (protocol-error-close-code c) (protocol-error-message c))
                     (finish-close (protocol-error-close-code c)
                                   (protocol-error-message c)))
                   (error (e)
                     (unless (conn-closed-p conn)
                       ;; This SSL warning can come from C and bubbles as a Lisp condition by cl+ssl
                       ;; and can look scary, when read-frame fails during closing. They are harmless
                       ;; if the connection is closing and we only warn about frame reading failure
                       ;; when the connection is in non-closing state.
                       (warn "Frame read error: ~A" e)
                       (funcall handler :error e)
                       (close-connection conn 1002 ""))
                     (finish-close 1002 "")))
               (declare (type (unsigned-byte 4) opcode)
                        (type (simple-array (unsigned-byte 8) (*)) payload)
                        (type boolean fin))
               (let ((len-payload (length payload)))
                 (declare (type fixnum len-payload))
                 (handler-case 
                     (cond
                       ((member opcode '(#x8 #x9 #xA))
                        (unless fin
                          (error 'fragmented-control-frame-error))
                        (unless (<= len-payload 125)
                          (error 'control-frame-too-large-error :size len-payload))
                        (case opcode
                          (#x8
                           (cond
                             ((= len-payload 1)
                              (error 'invalid-close-payload-error))
                             (t
                              (let* ((code (if (zerop len-payload)
                                               1005
                                               (+ (ash (aref payload 0) 8)
                                                  (aref payload 1))))
                                     (reason-bytes (if (> len-payload 2)
                                                       (subseq payload 2)
                                                       (make-array 0 :element-type '(unsigned-byte 8)))))
                                (declare (type (integer 0 65535) code)
                                         (type (array (unsigned-byte 8) (*)) reason-bytes))
                                (when (plusp len-payload)
                                  (unless (valid-close-status-p code)
                                    (error 'invalid-close-code-error :received-code code)))
                                (if (plusp (length reason-bytes))
                                    (let ((received-reason-str
                                            (if (reuse-text-message-strbuf conn)
                                                (handler-case
                                                    (let ((maybe-same-buf
                                                            (%utf8-decode-borrowed reason-bytes text-buf)))
                                                      (setf text-buf maybe-same-buf)
                                                      text-buf)
                                                  (reckless-utf8:utf8-decoding-error ()
                                                    (error 'invalid-utf8-error
                                                           :context :close-reason
                                                           :octets reason-bytes)))
                                                (handler-case
                                                    (babel:octets-to-string reason-bytes
                                                                            :encoding :utf-8
                                                                            :errorp t)
                                                  (babel-encodings:character-decoding-error ()
                                                    (error 'invalid-utf8-error
                                                           :context :close-reason
                                                           :octets reason-bytes))))))
                                      (declare (type string received-reason-str))
                                      ;; because finish-close / handler
                                      ;; may outlive the next reuse of text-buf...
                                      (when (reuse-text-message-strbuf conn)
                                        (setf received-reason-str (copy-seq received-reason-str)))
                                      ;; Reply (or no-op if we already sent a Close) then finish.
                                      (close-connection conn (if (zerop len-payload) 1000 code))
                                      (finish-close code received-reason-str))
                                    (progn
                                      (close-connection conn (if (zerop len-payload) 1000 code))
                                      (finish-close code)))))))
                          (#x9
                           (ignore-errors (write-frame-locked conn #xA payload))
                           (funcall handler :ping payload))
                          (#xA
                           (funcall handler :pong payload))))
                       ((or (= opcode #x1) (= opcode #x2) (= opcode #x0))
                        (cond
                          ((null msg-opcode)
                           (when (= opcode #x0)
                             (error 'unexpected-continuation-frame-error))
                           (if fin
                               ;; Single-frame message; we avoid more allocations here.
                               (deliver-payload opcode payload)
                               (let ((len len-payload))
                                 (setf msg-opcode opcode
                                       msg-buffer (make-array (max len 16)
                                                              :element-type '(unsigned-byte 8))
                                       msg-len 0)
                                 (when (plusp len)
                                   (replace msg-buffer payload)
                                   (setf msg-len len)))))
                          (t
                           (unless (= opcode #x0)
                             (error 'unexpected-data-frame-error :received-opcode opcode))
                           (locally
                               (declare (type (simple-array (unsigned-byte 8) (*)) msg-buffer))
                             (let ((need (+ msg-len len-payload))
                                   (dim  (array-dimension msg-buffer 0)))
                               (declare (type fixnum need dim))
                               (when (> need dim)
                                 (let ((new (make-array (max need (* 2 dim))
                                                        :element-type '(unsigned-byte 8))))
                                   (replace new msg-buffer :end1 msg-len)
                                   (setf msg-buffer new)))
                               (when (plusp len-payload)
                                 (replace msg-buffer payload :start1 msg-len)
                                 (incf msg-len len-payload))))
                           (when fin
                             (deliver-message)))))
                       (t
                        (error 'unknown-opcode-error :opcode opcode)))
                   (protocol-error (c)
                     (funcall handler :error c)
                     (close-connection conn (protocol-error-close-code c) (protocol-error-message c))
                     (finish-close (protocol-error-close-code c)
                                   (protocol-error-message c)))
                   (error (e)
                     ;; If close-connection from other thread causes the state to flip from :open
                     ;; to :closing or :closed, sending of message might signal. In this case
                     ;; this handler catches that and it's an no-op. Otherwise if the state is still
                     ;; :open, it's an unexpected error that needs warning and we close the connection
                     ;; immediately.
                     (unless (conn-closed-p conn)
                       (funcall handler :error e)
                       (warn "WebSocket listener error: ~A" e)
                       (ignore-errors
                        (close-connection conn 1002 "")))
                     (finish-close 1002 ""))))))
        (ignore-errors
         (if (conn-secure-p conn)
             (progn
               (close (conn-stream conn))
               (socket-close (conn-socket conn)))
             (socket-close (conn-socket conn))))
        ;; If unwrap-stream-p is t we use the following
        #|(ignore-errors
        (if (conn-secure-p conn)
        (close (conn-stream conn))
        (socket-close (conn-socket conn))))|#
        (multiple-value-bind (code reason)
            (bt:with-recursive-lock-held ((conn-lock conn))
              (values (conn-close-code conn) (conn-close-reason conn)))
          (funcall handler :close (cons code reason)))))))

