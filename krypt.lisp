
(defconstant +blocksize+ 4096)
(defconstant +mask+ #x8a5b6c23)

(defun enc (x) (logxor x +mask+))
(defun array-enc-to-int-le (a i)
  (let* ((x (+ (ash (aref a i) 0)
               (ash (aref a (+ i 1)) 8)
               (ash (aref a (+ i 2)) 16)
               (ash (aref a (+ i 3)) 24)))
         (result (enc x)))
    (setf (aref a i) (logand #xff (ash result 0)))
    (setf (aref a (+ i 1)) (logand #xff (ash result -8)))
    (setf (aref a (+ i 2)) (logand #xff (ash result -16)))
    (setf (aref a (+ i 3)) (logand #xff (ash result -24)))
  ))

(defun encrypt (buf size)
  (let ((nblocks (floor size 4))
        (j (rem size 4))
        (mask (make-array 4 :initial-contents '(#x23 #x6c #x5b #x8a))))
    (loop for i from 0 below nblocks
          do (array-enc-to-int-le buf (* i 4)))
    (if (> j 0)
        (loop for i from 0 below j
              for remain from (* nblocks 4)
              do (setf (aref buf remain) (logxor (aref buf remain) (aref mask i))))
        )
    )
  )

(defun decrypt (buf offs size)
  (let ((shift (rem offs 4))
        (j (rem size 4))
        (nblocks (floor size 4))
        (mask (make-array 4 :initial-contents '(#x23 #x6c #x5b #x8a))))
    (if (not (eq shift 0))
        (progn
          (setf shift (logior (ash +mask+ (- (* 8 (- 4 shift))))
                              (ash +mask+ (* 8 shift))))
          (loop for i from 0 below 4
                do (setf (aref mask i) (logand (ash +mask+ (* 8 i)) #xff)))))
    (loop for i from 0 below nblocks
          do (array-enc-to-int-le buf (* i 4)))
    (if (> j 0)
        (loop for i from 0 below j
              for remain from (* nblocks 4)
              do (setf (aref buf remain) (logxor (aref buf remain) (aref mask i))))
        )
    )
  )

(defun cipher-file (dst src decryptp)
  (with-open-file (in src
                   :direction :input
                   :if-does-not-exist :error
                   :element-type '(unsigned-byte 8))
    (with-open-file (out dst
                     :direction :output
                     :if-exists :supersede
                     :if-does-not-exist :create
                     :element-type '(unsigned-byte 8))
      (let ((buf (make-array +blocksize+ :element-type (stream-element-type in)))
            (nblocks (floor (- (+ (file-length in)
                                  +blocksize+)
                               1)
                            +blocksize+)))
        (loop for pos = (read-sequence buf in)
              for i from 0 to nblocks
              while (and (< i nblocks) (plusp pos))
              do (progn
                   (if decryptp
                       (decrypt buf 0 pos)
                       (encrypt buf pos))
                   (write-sequence buf out :end pos)))
        )
      )
    )
  )
