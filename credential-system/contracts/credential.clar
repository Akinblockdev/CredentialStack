;; Credential Issuing Contract
;; Allows authorized issuers to grant and verify credentials

(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-ISSUER (err u101))
(define-constant ERR-CREDENTIAL-EXISTS (err u102))
(define-constant ERR-INVALID-CREDENTIAL (err u103))
(define-constant ERR-INVALID-PRINCIPAL (err u104))
(define-constant ERR-INVALID-EXPIRY (err u105))
(define-constant ERR-INVALID-METADATA (err u106))
(define-constant MAX-METADATA-LENGTH u256)

;; Data vars
(define-data-var admin principal tx-sender)

;; Maps
(define-map authorized-issuers principal bool)
(define-map credentials 
    {holder: principal, type: (string-ascii 64)}
    {issuer: principal, 
     issued-at: uint,
     expiry: uint,
     metadata: (string-utf8 256),
     revoked: bool})

;; Helper functions
(define-private (validate-principal (address principal))
    (match (principal-destruct? address)
        success true
        error false))

(define-private (validate-expiry (expiry-height uint))
    (>= expiry-height block-height))

(define-private (validate-metadata (data (string-utf8 256)))
    (and 
        (>= MAX-METADATA-LENGTH (len data))
        (> (len data) u0)))

;; Read-only functions
(define-read-only (is-issuer (address principal))
    (default-to false (map-get? authorized-issuers address)))

(define-read-only (get-credential 
    (holder principal) 
    (type (string-ascii 64)))
    (map-get? credentials {holder: holder, type: type}))

(define-read-only (is-credential-valid 
    (holder principal) 
    (type (string-ascii 64)))
    (match (get-credential holder type)
        valid (and 
                (not (get revoked valid))
                (>= (get expiry valid) block-height))
        false))

;; Public functions
(define-public (add-issuer (issuer principal))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
        (asserts! (validate-principal issuer) ERR-INVALID-PRINCIPAL)
        (map-set authorized-issuers issuer true)
        (ok true)))

(define-public (remove-issuer (issuer principal))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
        (asserts! (validate-principal issuer) ERR-INVALID-PRINCIPAL)
        (asserts! (is-issuer issuer) ERR-INVALID-ISSUER)
        (map-delete authorized-issuers issuer)
        (ok true)))

(define-public (issue-credential 
    (holder principal)
    (type (string-ascii 64))
    (expiry uint)
    (metadata (string-utf8 256)))
    (begin
        (asserts! (is-issuer tx-sender) ERR-NOT-AUTHORIZED)
        (asserts! (validate-principal holder) ERR-INVALID-PRINCIPAL)
        (asserts! (validate-expiry expiry) ERR-INVALID-EXPIRY)
        (asserts! (validate-metadata metadata) ERR-INVALID-METADATA)
        (asserts! (is-none (get-credential holder type)) ERR-CREDENTIAL-EXISTS)
        (map-set credentials 
            {holder: holder, type: type}
            {issuer: tx-sender,
             issued-at: block-height,
             expiry: expiry,
             metadata: metadata,
             revoked: false})
        (ok true)))

(define-public (revoke-credential
    (holder principal)
    (type (string-ascii 64)))
    (let ((credential (unwrap! (get-credential holder type) ERR-INVALID-CREDENTIAL)))
        (begin
            (asserts! (or 
                (is-eq tx-sender (var-get admin))
                (is-eq tx-sender (get issuer credential)))
                ERR-NOT-AUTHORIZED)
            (map-set credentials
                {holder: holder, type: type}
                (merge credential {revoked: true}))
            (ok true))))