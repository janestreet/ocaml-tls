open Async
open Core

type 'addr t constraint 'addr = [< Socket.Address.t]

type tracer = Sexplib.Sexp.t -> unit

exception Bad_fd
(** Raised by internal reader/writer when [read] or [write] {i syscall} raises
   [EBADF] Unix-exception. *)

exception Tls_alert of Tls.Packet.alert_type
(** Raised by the TLS reader when it handles input. *)

exception Tls_failure of Tls.Engine.failure
(** Raised by the TLS reader when it handles input. *)

exception Tls_close
(** Raise by the TLS state when it retrieves end-of-input state but user want to
   write something or renegociate. *)

exception Tls_state_not_ready_to_send
(** Raised by the TLS state when it not able to send something. *)

exception Tls_can't_renegotiate
(** Raised by the TLS state when it not able to renegociate. *)

exception Tls_socket_closed
(** Raised by [accept] when socket is closed. *)

val server_of_socket :
     ?tracer:tracer
  -> Tls.Config.server
  -> ([`Active], ([< Socket.Address.t] as 'a)) Socket.t
  -> 'a t Deferred.t

val client_of_socket :
     ?tracer:tracer
  -> Tls.Config.client
  -> ?host:string
  -> ([`Active], ([< Socket.Address.t] as 'a)) Socket.t
  -> 'a t Deferred.t

(** Low level API. *)

val accept :
     ?tracer:tracer
  -> Tls.Config.server
  -> ([`Passive], ([< Socket.Address.t] as 'a)) Socket.t
  -> ('a t * 'a) Or_error.t Deferred.t

val connect :
     ?tracer:tracer
  -> Tls.Config.client
  -> ([< `Bound | `Unconnected], ([< Socket.Address.t] as 'a)) Socket.t
  -> 'a
  -> 'a t Or_error.t Deferred.t

val read :
  'a t -> Bigstring.t -> int -> int -> [`Eof | `Ok of int] Deferred.t

val write : 'a t -> Bigstring.t -> int -> int -> unit Deferred.t

val close : error:(exn -> unit Deferred.t) -> 'a t -> unit Deferred.t

val reneg :
     ?authenticator:X509.Authenticator.a
  -> ?acceptable_cas:X509.distinguished_name list
  -> ?cert:Tls.Config.own_cert
  -> ?drop:bool
  -> 'a t
  -> unit Deferred.t

val epoch : 'a t -> [`Ok of Tls.Core.epoch_data | `Error]

(** High level API. *)

val reader_and_writer :
     error:(exn -> unit Deferred.t)
  -> 'a t
  -> (Reader.t * Writer.t * unit Deferred.t) Deferred.t
