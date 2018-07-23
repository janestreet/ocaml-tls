open Async

type 'addr t constraint 'addr = [< Socket.Address.t ]
type tracer = Sexplib.Sexp.t -> unit

exception Tls_alert of Tls.Packet.alert_type
exception Tls_failure of Tls.Engine.failure
exception Tls_close

val server_of_socket: ?tracer:tracer -> Tls.Config.server -> ([ `Active ], [< Socket.Address.t ] as 'a) Socket.t -> 'a t Deferred.t
val client_of_socket: ?tracer:tracer -> Tls.Config.client -> ?host:string -> ([ `Active ], [< Socket.Address.t ] as 'a) Socket.t -> 'a t Deferred.t

(** Low level API. *)

val accept: ?tracer:tracer -> Tls.Config.server -> ([ `Passive ], [< Socket.Address.t ] as 'a) Socket.t -> ('a t * 'a) Deferred.t
val connect: ?tracer:tracer -> Tls.Config.client -> ([< `Bound | `Unconnected ], [< Socket.Address.t ] as 'a) Socket.t -> 'a -> 'a t Deferred.t

val read: 'a t -> Core.Bigstring.t -> int -> int -> [ `Eof | `Ok of int ] Deferred.t
val write: 'a t -> Core.Bigstring.t -> int -> int -> unit Deferred.t
val close: error:(exn -> unit Deferred.t) -> 'a t -> unit Deferred.t

val reneg:
  ?authenticator:X509.Authenticator.a ->
  ?acceptable_cas:X509.distinguished_name list ->
  ?cert:Tls.Config.own_cert ->
  ?drop:bool ->
  'a t -> unit Deferred.t

val epoch: 'a t -> [ `Ok of Tls.Core.epoch_data | `Error ]

(** High level API. *)

val reader_and_writer: error:(exn -> unit Deferred.t) -> 'a t -> (Reader.t * Writer.t * unit Deferred.t) Deferred.t

