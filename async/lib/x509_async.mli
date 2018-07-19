open Async

(** X.509 certificate handling using Async. *)

(** Private material: a certificate chain and a RSA private key. *)
type priv = X509.t list * Nocrypto.Rsa.priv

(** Authenticator. *)
type authenticator = X509.Authenticator.a

(** [private_of_pems ~cert ~priv_key] is [priv], after reading the private key
   and certificate chain fro mthe given PEM-encoded files. *)
val private_of_pems: cert:Fpath.t -> priv_key:Fpath.t -> (priv, [ `Msg of string ]) result Deferred.t

(** [certs_of_pem file] is [certificates], which are read from the PEM-encoded
   [file]. *)
val certs_of_pem: Fpath.t -> (X509.t list, [ `Msg of string ]) result Deferred.t

(** [certs_of_pem_dir dir] is [certificates], which are read from all
   PEM-encoded files in [dir]. *)
val certs_of_pem_dir: ?ext:Fpath.ext -> Fpath.t -> X509.t list Deferred.t

(** [authenticator methods] constructs an [authenticator] using the specified
   method and data. *)
val authenticator:
  [ `Ca_file of Fpath.t
  | `Ca_dir of Fpath.t
  | `Key_fingerprints of Nocrypto.Hash.hash * (string * Cstruct.t) list
  | `Hex_key_fingerprints of Nocrypto.Hash.hash * (string * string) list
  | `No_authentication ] -> (authenticator, [ `Msg of string ]) result Deferred.t
