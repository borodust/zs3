;;;;
;;;; Copyright (c) 2008 Zachary Beane, All Rights Reserved
;;;;
;;;; Redistribution and use in source and binary forms, with or without
;;;; modification, are permitted provided that the following conditions
;;;; are met:
;;;;
;;;;   * Redistributions of source code must retain the above copyright
;;;;     notice, this list of conditions and the following disclaimer.
;;;;
;;;;   * Redistributions in binary form must reproduce the above
;;;;     copyright notice, this list of conditions and the following
;;;;     disclaimer in the documentation and/or other materials
;;;;     provided with the distribution.
;;;;
;;;; THIS SOFTWARE IS PROVIDED BY THE AUTHOR 'AS IS' AND ANY EXPRESSED
;;;; OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;;;; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;;;; ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
;;;; DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;;;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
;;;; GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
;;;; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
;;;; WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;;; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;;; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;
;;;; crypto.lisp

(in-package #:zs3)


(defclass digester ()
  ((digester
    :initarg :digester
    :accessor digester)
   (newline
    :initarg :newline
    :accessor newline
    :allocation :class)
   (signed-stream
    :initarg :signed-stream
    :accessor signed-stream))
  (:default-initargs
   :signed-stream (make-string-output-stream)
   :newline (make-array 1 :element-type '(unsigned-byte 8)
                        :initial-element 10)))

(defgeneric add-string (string digester))
(defgeneric add-newline (digester))

(defgeneric add-line (string digester)
  (:method (string digester)
    (add-string string digester)
    (add-newline digester)))

(defgeneric digest64 (digester))
(defgeneric digest-hex (digester))


(defclass hmac-digester (digester) ())

(defun make-hmac-digester (key)
  (make-instance 'hmac-digester
		 :digester (make-hmac (string-octets key))))

(defmethod add-string (string (digester hmac-digester))
  (write-string string (signed-stream digester))
  (ironclad:update-hmac (digester digester) (string-octets string)))

(defmethod add-newline ((digester hmac-digester))
  (terpri (signed-stream digester))
  (ironclad:update-hmac (digester digester) (newline digester)))

(defmethod digest64 ((digester hmac-digester))
  (base64:usb8-array-to-base64-string
   (ironclad:hmac-digest (digester digester))))

(defmethod digest-hex ((digester hmac-digester))
  (ironclad:byte-array-to-hex-string
   (ironclad:hmac-digest (digester digester))))


(defclass sha256-digester (digester)())

(defun make-sha256-digester ()
  (make-instance 'sha256-digester
		 :digester (ironclad:make-digest :sha256)))

(defmethod add-string (string (digester sha256-digester))
  (write-string string (signed-stream digester))
  (ironclad:update-digest (digester digester) (string-octets string)))

(defmethod add-newline ((digester sha256-digester))
  (terpri (signed-stream digester))
  (ironclad:update-digest (digester digester) (newline digester)))

(defmethod digest64 ((digester sha256-digester))
  (base64:usb8-array-to-base64-string
   (ironclad:produce-digest (digester digester))))

(defmethod digest-hex ((digester sha256-digester))
  (ironclad:byte-array-to-hex-string
   (ironclad:produce-digest (digester digester))))



(defun file-md5 (file)
   (ironclad:digest-file :md5 file))

(defun file-md5/b64 (file)
  (base64:usb8-array-to-base64-string (file-md5 file)))

(defun file-md5/hex (file)
  (ironclad:byte-array-to-hex-string (file-md5 file)))

(defun file-sha256 (file)
   (ironclad:digest-file :sha256 file))

(defun file-sha256/hex (file)
  (ironclad:byte-array-to-hex-string
   (file-sha256 file)))

(defun vector-sha256/hex (octets)
  (ironclad:byte-array-to-hex-string
   (ironclad:digest-sequence :sha256 octets)))

(defun string-sha256/hex (text)
  (vector-sha256/hex (string-octets text)))

(defun vector-md5/b64 (vector)
  (base64:usb8-array-to-base64-string
   (ironclad:digest-sequence :md5 vector)))

(defun file-etag (file)
  (format nil "\"~A\"" (file-md5/hex file)))

(defun sign-string (key string)
  (let ((digester (make-hmac-digester key)))
    (add-string string digester)
    (digest64 digester)))

(defun make-hmac (&optional key)
  (ironclad:make-hmac (or key (make-array 0 :element-type '(unsigned-byte 8))) :sha1))

(defun hmac-digest (hmac key-octets text)
  (reinitialize-instance hmac :key key-octets)
  (ironclad:update-hmac hmac (string-octets text))
  (ironclad:hmac-digest hmac))

