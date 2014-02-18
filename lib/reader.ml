open Packet
open Core

let parse_hdr buf =
  let content_type = match int_to_content_type (get_tls_h_content_type buf) with
    | Some x -> x
    | None -> assert false
  in
  let major = get_tls_h_major_version buf in
  let minor = get_tls_h_minor_version buf in
  let version = (major, minor) in
  let len = get_tls_h_length buf in
  let payload = Cstruct.sub buf 5 len in
  ( { content_type; version }, payload, len + 5)

let parse_alert buf =
  let level = Cstruct.get_uint8 buf 0 in
  let lvl = match int_to_alert_level level with
    | Some x -> x
    | None -> assert false
  in
  let desc = Cstruct.get_uint8 buf 1 in
  let msg = match int_to_alert_type desc with
    | Some x -> x
    | None -> assert false
  in
  (lvl, msg)

let rec get_certificate_types buf acc = function
  | 0 -> acc
  | n -> let ctype =
           match int_to_client_certificate_type (Cstruct.get_uint8 buf 0) with
           | Some x -> x
           | None -> assert false
         in get_certificate_types (Cstruct.shift buf 1) (ctype :: acc) (n - 1)

let rec get_cas buf acc =
  match (Cstruct.len buf) with
  | 0 -> acc
  | n ->
     let len = Cstruct.BE.get_uint16 buf 0 in
     let name = Cstruct.copy buf 2 len in
     get_cas (Cstruct.shift buf (2 + len)) (name :: acc)

let parse_certificate_request buf =
  let typeslen = Cstruct.get_uint8 buf 0 in
  let certificate_types = get_certificate_types (Cstruct.shift buf 1) [] typeslen in
  let buf = Cstruct.shift buf (1 + typeslen) in
  let calength = Cstruct.BE.get_uint16 buf 0 in
  let certificate_authorities = get_cas (Cstruct.sub buf 2 calength) [] in
  { certificate_types ; certificate_authorities }

let get_compression_method buf =
  match int_to_compression_method (Cstruct.get_uint8 buf 0) with
  | Some x -> x
  | None -> assert false

let get_compression_methods buf =
  let rec go buf acc = function
    | 0 -> acc
    | n -> go (Cstruct.shift buf 1) (get_compression_method buf :: acc) (n - 1)
  in
  let len = Cstruct.get_uint8 buf 0 in
  let methods = go (Cstruct.shift buf 1) [] len in
  (methods, len + 1)

let get_ciphersuite buf =
  match Ciphersuite.int_to_ciphersuite (Cstruct.BE.get_uint16 buf 0) with
  | Some x -> x
  | None -> assert false

let get_ciphersuites buf =
  let rec go buf acc = function
    | 0 -> acc
    | n -> go (Cstruct.shift buf 2) ((get_ciphersuite buf) :: acc) (n - 1)
  in
  let len = Cstruct.BE.get_uint16 buf 0 in
  let suites = go (Cstruct.shift buf 2) [] (len / 2) in
  (List.rev suites, len + 2)

let get_hostnames buf =
  let list_length = Cstruct.BE.get_uint16 buf 0 in
  let rec go buf acc =
    match (Cstruct.len buf) with
    | 0 -> acc
    | n ->
       let name_type = Cstruct.get_uint8 buf 0 in
       match name_type with
       | 0 ->
          let hostname_length = Cstruct.BE.get_uint16 buf 1 in
          go (Cstruct.shift buf (3 + hostname_length)) ((Cstruct.copy buf 3 hostname_length) :: acc)
       | _ -> assert false
  in
  go (Cstruct.sub buf 2 list_length) []

let get_fragment_length buf =
  int_to_max_fragment_length (Cstruct.get_uint8 buf 0)

let get_named_curve buf =
  match int_to_named_curve_type (Cstruct.BE.get_uint16 buf 0) with
  | Some x -> x
  | None -> assert false

let get_elliptic_curves buf =
  let rec go buf acc = match (Cstruct.len buf) with
    | 0 -> acc
    | n -> go (Cstruct.shift buf 2) (get_named_curve buf :: acc)
  in
  let len = Cstruct.BE.get_uint16 buf 0 in
  go (Cstruct.sub buf 2 len) []

let get_ec_point_format buf =
  let rec go buf acc = match (Cstruct.len buf) with
    | 0 -> acc
    | n ->
       let fmt = match int_to_ec_point_format (Cstruct.get_uint8 buf 0) with
         | Some x -> x
         | None -> assert false
       in
       go (Cstruct.shift buf 1) (fmt :: acc)
  in
  let len = Cstruct.get_uint8 buf 0 in
  go (Cstruct.sub buf 1 len) []

let get_extension buf =
  let etype = Cstruct.BE.get_uint16 buf 0 in
  let len = Cstruct.BE.get_uint16 buf 2 in
  let buf = Cstruct.sub buf 4 len in
  let data = match (int_to_extension_type etype) with
    | Some SERVER_NAME -> Hostname (get_hostnames buf)
    | Some MAX_FRAGMENT_LENGTH -> MaxFragmentLength (get_fragment_length buf)
    | Some ELLIPTIC_CURVES -> EllipticCurves (get_elliptic_curves buf)
    | Some EC_POINT_FORMATS -> ECPointFormats (get_ec_point_format buf)
    | Some x -> Unsupported x
    | None -> assert false
  in
  (data, 4 + len)

let get_extensions buf =
  let rec go buf acc =
    match (Cstruct.len buf) with
    | 0 -> acc
    | n ->
       let extension, esize = get_extension buf in
       go (Cstruct.shift buf esize) (extension :: acc)
  in
  let len = Cstruct.BE.get_uint16 buf 0 in
  (go (Cstruct.sub buf 2 len) [], Cstruct.shift buf (2 + len))


let get_varlength buf bytes =
  let rec go buf len = function
    | 0 -> len
    | n -> go (Cstruct.shift buf 1) ((Cstruct.get_uint8 buf 0) + len * 0x100) (n - 1)
  in
  let len = go buf 0 bytes in
  match len with
  | 0 -> (None, 1)
  | n -> let total = n + bytes in
         (Some (Cstruct.sub buf n total), total)

let parse_client_hello buf =
  let major = get_c_hello_major_version buf in
  let minor = get_c_hello_minor_version buf in
  let version = (major, minor) in
  let random = get_c_hello_random buf in
  let sessionid, slen = get_varlength (Cstruct.shift buf 34) 1 in
  let ciphersuites, clen = get_ciphersuites (Cstruct.shift buf (34 + slen)) in
  let _, dlen = get_compression_methods (Cstruct.shift buf (34 + slen + clen)) in
  let extensions, elen = get_extensions (Cstruct.shift buf (34 + slen + clen + dlen)) in
  (* assert that dlen is small *)
  { version ; random ; sessionid ; ciphersuites ; extensions }

let parse_server_hello buf : server_hello =
  let major = get_c_hello_major_version buf in
  let minor = get_c_hello_minor_version buf in
  let version = (major, minor) in
  let random = get_c_hello_random buf in
  let sessionid, slen = get_varlength (Cstruct.shift buf 34) 1 in
  let ciphersuites = get_ciphersuite (Cstruct.shift buf (34 + slen)) in
  let _ = get_compression_method (Cstruct.shift buf (34 + slen + 2)) in
  let extensions, elen = get_extensions (Cstruct.shift buf (34 + slen + 2 + 1)) in
  (* assert that dlen is small *)
  { version ; random ; sessionid ; ciphersuites ; extensions }

let get_certificate buf =
  let len = get_uint24_len buf in
  ((Cstruct.sub buf 3 len), len + 3)

let get_certificates buf =
  let rec go buf acc =
            match (Cstruct.len buf) with
            | 0 -> acc
            | n -> let cert, size = get_certificate buf in
                   go (Cstruct.shift buf size) (cert :: acc)
  in
  let len = get_uint24_len buf in
  go (Cstruct.sub buf 3 len) []

let parse_rsa_parameters buf =
  let mlength = Cstruct.BE.get_uint16 buf 0 in
  let rsa_modulus = Cstruct.sub buf 2 mlength in
  let buf = Cstruct.shift buf (2 + mlength) in
  let elength = Cstruct.BE.get_uint16 buf 0 in
  let rsa_exponent = Cstruct.sub buf 2 elength in
  ({ rsa_modulus ; rsa_exponent }, 4 + mlength + elength)

let parse_dsa_parameters buf =
  let plength = Cstruct.BE.get_uint16 buf 0 in
  let dh_p = Cstruct.sub buf 2 plength in
  let buf = Cstruct.shift buf (2 + plength) in
  let glength = Cstruct.BE.get_uint16 buf 0 in
  let dh_g = Cstruct.sub buf 2 glength in
  let buf = Cstruct.shift buf (2 + plength) in
  let yslength = Cstruct.BE.get_uint16 buf 0 in
  let dh_Ys = Cstruct.sub buf 2 yslength in
  ({ dh_p ; dh_g; dh_Ys }, 6 + plength + glength + yslength)

let parse_ec_curve buf =
  let al = Cstruct.get_uint8 buf 0 in
  let a = Cstruct.sub buf 1 al in
  let buf = Cstruct.shift buf (1 + al) in
  let bl = Cstruct.get_uint8 buf 0 in
  let b = Cstruct.sub buf 1 bl in
  let buf = Cstruct.shift buf (1 + bl) in
  ({ a ; b }, buf)

let parse_ec_prime_parameters buf =
  let plen = Cstruct.get_uint8 buf 0 in
  let prime = Cstruct.sub buf 1 plen in
  let buf = Cstruct.shift buf (1 + plen) in
  let curve, buf = parse_ec_curve buf in
  let blen = Cstruct.get_uint8 buf 0 in
  let base = Cstruct.sub buf 1 blen in
  let buf = Cstruct.shift buf (1 + blen) in
  let olen = Cstruct.get_uint8 buf 0 in
  let order = Cstruct.sub buf 1 olen in
  let buf = Cstruct.shift buf (1 + olen) in
  let cofactorlength = Cstruct.get_uint8 buf 0 in
  let cofactor = Cstruct.sub buf 1 cofactorlength in
  let buf = Cstruct.shift buf (1 + cofactorlength) in
  let publiclen = Cstruct.get_uint8 buf 0 in
  let public = Cstruct.sub buf 1 publiclen in
  let buf = Cstruct.shift buf (1 + publiclen) in
  ({ prime ; curve ; base ; order ; cofactor ; public }, buf)

let parse_ec_char_parameters buf =
  let m = Cstruct.BE.get_uint16 buf 0 in
  let basis = match int_to_ec_basis_type (Cstruct.get_uint8 buf 2) with
    | Some x -> x
    | None -> assert false
  in
  let buf = Cstruct.shift buf 3 in
  let ks, buf = match basis with
    | TRINOMIAL ->
       let len = Cstruct.get_uint8 buf 0 in
       ([Cstruct.sub buf 1 len], Cstruct.shift buf (len + 1))
    | PENTANOMIAL ->
       let k1len = Cstruct.get_uint8 buf 0 in
       let k1 = Cstruct.sub buf 1 k1len in
       let buf = Cstruct.shift buf (k1len + 1) in
       let k2len = Cstruct.get_uint8 buf 0 in
       let k2 = Cstruct.sub buf 1 k2len in
       let buf = Cstruct.shift buf (k2len + 1) in
       let k3len = Cstruct.get_uint8 buf 0 in
       let k3 = Cstruct.sub buf 1 k3len in
       ([k1; k2; k3], Cstruct.shift buf (k3len + 1))
  in
  let curve, buf = parse_ec_curve buf in
  let blen = Cstruct.get_uint8 buf 0 in
  let base = Cstruct.sub buf 1 blen in
  let buf = Cstruct.shift buf (1 + blen) in
  let olen = Cstruct.get_uint8 buf 0 in
  let order = Cstruct.sub buf 1 olen in
  let buf = Cstruct.shift buf (1 + olen) in
  let cofactorlength = Cstruct.get_uint8 buf 0 in
  let cofactor = Cstruct.sub buf 1 cofactorlength in
  let buf = Cstruct.shift buf (1 + cofactorlength) in
  let publiclen = Cstruct.get_uint8 buf 0 in
  let public = Cstruct.sub buf 1 publiclen in
  let buf = Cstruct.shift buf (1 + publiclen) in
  ({ m ; basis ; ks ; curve ; base ; order ; cofactor ; public }, buf)

let parse_ec_parameters buf =
  let pbuf = Cstruct.shift buf 1 in
  match int_to_ec_curve_type (Cstruct.get_uint8 buf 0) with
  | Some EXPLICIT_PRIME ->
     let ep, buf = parse_ec_prime_parameters pbuf in
     (ExplicitPrimeParameters ep, buf)
  | Some EXPLICIT_CHAR2 ->
     let ec, buf = parse_ec_char_parameters pbuf in
     (ExplicitCharParameters ec, buf)
  | Some NAMED_CURVE ->
     let curve = get_named_curve pbuf in
     let plen = Cstruct.get_uint8 buf 2 in
     let public = Cstruct.sub buf 3 plen in
     (NamedCurveParameters (curve, public), Cstruct.shift buf (3 + plen))
  | _ -> assert false

let parse_sig buf =
  let len = Cstruct.BE.get_uint16 buf 0 in
  Cstruct.sub buf 2 len

let parse_server_key_exchange buf =
  let len = Cstruct.BE.get_uint16 buf 0 in
  let buf = Cstruct.sub buf 2 len in
  (* need to get from selected ciphersuite what I should parse! *)
  let dh, size = parse_dsa_parameters buf in
  let sign = DSA (parse_sig (Cstruct.shift buf size)) in
  DiffieHellman (dh, sign)


let parse_handshake buf =
  let handshake_type = int_to_handshake_type (Cstruct.get_uint8 buf 0) in
  let len = get_uint24_len (Cstruct.shift buf 1) in
  let payload = Cstruct.sub buf 4 len in
  match handshake_type with
    | Some HELLO_REQUEST -> HelloRequest
    | Some CLIENT_HELLO -> ClientHello (parse_client_hello payload)
    | Some SERVER_HELLO -> ServerHello (parse_server_hello payload)
    | Some CERTIFICATE -> Certificate (get_certificates payload)
    | Some SERVER_KEY_EXCHANGE -> ServerKeyExchange (parse_server_key_exchange payload)
    | Some SERVER_HELLO_DONE -> ServerHelloDone
    | Some CERTIFICATE_REQUEST -> CertificateRequest (parse_certificate_request payload)
    | Some CLIENT_KEY_EXCHANGE -> ClientKeyExchange (ClientRsa (Cstruct.sub payload 0 len))
    | Some FINISHED -> Finished (Cstruct.sub payload 0 12)
    | _ -> assert false

let parse buf =
  let header, buf, len = parse_hdr buf in
  let body = match header.content_type with
    | HANDSHAKE          -> TLS_Handshake (parse_handshake buf)
    | CHANGE_CIPHER_SPEC -> TLS_ChangeCipherSpec
    | ALERT              -> TLS_Alert (parse_alert buf)
    | _ -> assert false
  in ((header, body), len)

