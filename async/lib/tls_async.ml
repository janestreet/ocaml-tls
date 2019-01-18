module U = Unix
open Core
open Async

exception Bad_fd

module Async_cstruct = struct
  (* XXX(dinosaure): this module generate from a socket:
     - a safe reader and a safe writer without exception leaks
     - non-blocking reader/writer iff socket handles it
     - semantically, writer writes entirely the buffer (it returns unit)
     - semantically, reader informs if socket is close ([`Eof]) or not *)

  let protect ~name ~f socket a =
    Monitor.try_with ~name (fun () ->
        f a
        >>= fun res ->
        match Socket.getopt socket Socket.Opt.error with
        (* XXX(dinosaure): see [sockopt.c], return 0 if nothing. *)
        | 0 -> return (Ok res)
        | errno ->
            return
              (Error (U.Unix_error (Unix.Error.of_system_int ~errno, name, "")))
    )
    >>= function Ok res -> return res | Error exn -> return (Error exn)

  type 'kind buffer = Cstruct.t constraint 'kind = [< `Read | `Write]

  let make_writer fd : [`Write] buffer -> [`Ok of int | `Closed | `Bad_fd | `Exn of exn] Deferred.t =
    (* XXX(dinosaure): this code is a part of [faraday] project and benefits on
       a non-blocking writer when it's possible. *)
    let finish result =
      let open Unix.Error in
      match result with
      | `Ok n -> return (`Ok n)
      | `Already_closed -> return `Closed
      | `Error (Unix.Unix_error ((EWOULDBLOCK | EAGAIN), _, _)) -> (
          Fd.ready_to fd `Write
          >>| function
          | `Bad_fd -> `Bad_fd | `Closed -> `Closed | `Ready -> `Ok 0 )
      | `Error (Unix.Unix_error (EBADF, _, _)) -> return `Bad_fd
      | `Error exn ->
          Deferred.don't_wait_for (Fd.close fd) ;
          return (`Exn exn)
    in
    (* XXX(dinosaure): exception leak. *)
    fun {Cstruct.buffer= buf; off= pos; len} ->
      if Fd.supports_nonblock fd then
        finish
          (Fd.syscall fd ~nonblocking:true (fun fd ->
               Bigstring.write_assume_fd_is_nonblocking ~pos ~len fd buf ))
      else
        Fd.syscall_in_thread fd ~name:"writer" (fun fd ->
            Bigstring.write ~pos ~len fd buf )
        >>= finish

  let make_reader fd : [`Read] buffer -> [`Ok of int | `Eof | `Bad_fd | `Exn of exn] Deferred.t =
    let cstruct_to_bigstring {Cstruct.buffer= buf; off= pos; len} f =
      f buf ~pos ~len
    in
    let rec finish fd buf result =
      let open Unix.Error in
      match result with
      | `Already_closed | `Ok 0 -> return `Eof
      (* XXX(dinosaure): not sure to return [`Eof] when syscall returns [0]. *)
      | `Ok n -> return (`Ok n)
      | `Error (Unix.Unix_error ((EWOULDBLOCK | EAGAIN), _, _)) -> (
          Fd.ready_to fd `Read
          >>= function
          | `Bad_fd -> return `Bad_fd | `Closed -> return `Eof | `Ready -> go fd buf
          (* XXX(dinosaure): ready to read again. *) )
      | `Error (Unix.Unix_error (EBADF, _, _)) -> return `Bad_fd
      | `Error exn ->
          Deferred.don't_wait_for (Fd.close fd) ;
          return (`Exn exn)
    (* XXX(dinosaure): exception leak. *)
    and go fd buf =
      if Fd.supports_nonblock fd then
        finish fd buf
        @@ Fd.syscall fd ~nonblocking:true
        @@ fun fd ->
        cstruct_to_bigstring buf
        @@ fun buf ~pos ~len ->
        Unix.Syscall_result.Int.ok_or_unix_error_exn ~syscall_name:"read"
        @@ Bigstring.read_assume_fd_is_nonblocking fd buf ~pos ~len
      else
        ( Fd.syscall_in_thread fd ~name:"read"
        @@ fun fd ->
        cstruct_to_bigstring buf
        @@ fun buf ~pos ~len -> Bigstring.read fd buf ~pos ~len )
        >>= finish fd buf
    in
    go fd

  type writer = [`Write] buffer -> (unit, exn) result Deferred.t

  type reader = [`Read] buffer -> ([`Ok of int | `Eof], exn) result Deferred.t
  type reader_return = [ `Ok of int | `Eof ]

  (* XXX(dinosaure): at this stage, no exception leaks are possible. *)

  let reader_from_socket socket : reader =
    let fd = Socket.fd socket in
    (fun buffer -> (protect ~name:"read" ~f:(make_reader fd) socket buffer) >>| function
       | Ok #reader_return as v -> v
       | Ok `Bad_fd -> Error Bad_fd
       | Ok (`Exn exn) -> Error exn
       | Error _ as err -> err)

  let writer_from_socket socket : writer =
    let fd = Socket.fd socket in
    let wr cs = protect ~name:"write" ~f:(make_writer fd) socket cs in
    let rec wrf wr = function
      | cs when Cstruct.len cs = 0 -> return (Ok ())
      | cs -> (
          wr cs
          >>= function
          | Ok `Bad_fd -> return (Error Bad_fd)
          | Ok (`Exn exn) -> return (Error exn)
          | Ok (`Ok n) -> wrf wr (Cstruct.shift cs n)
          | Ok `Closed -> return (Ok ())
          | Error _ as err -> return err )
    in
    wrf wr
end

type tracer = Sexplib.Sexp.t -> unit

type 'addr t =
  { socket: ([`Active], 'addr) Socket.t
  ; tracer: tracer option
  ; recv_buf: Cstruct.t
  ; mutable state: state
  ; mutable linger: Cstruct.t option }

and state = [`Active of Tls.Engine.state | `Eof | `Error of exn]

let tracing t f =
  match t.tracer with None -> f () | Some hook -> Tls.Tracing.active ~hook f

exception Tls_alert of Tls.Packet.alert_type

exception Tls_failure of Tls.Engine.failure

exception Tls_close

let with_some f = function Some x -> f x | None -> return ()

(* XXX(dinosaure): from this wrapper, [`Error] can appear in any case on
   [t.state]. we short-cut control-flow by raising exception - but to be safe,
   after [rd] or [wr], an [`Error] should raise exception too. *)

let rd, wr =
  let recording_errors ~error safe_computation t cs =
    safe_computation t.socket cs
    >>= function
    | Ok res -> return res
    | Error exn ->
        t.state <- `Error exn ;
        return error
        (* we save the error in the state and see what happen next. We return a /safe/ value,
           however, any next computation should see [t.state] before to do anything. *)
        (* raise exn *)
  in
  (* exception leaks *)
  ( recording_errors ~error:(`Ok 0) Async_cstruct.reader_from_socket
  , recording_errors ~error:() Async_cstruct.writer_from_socket )

let rec rd_react t : [`Ok of Cstruct.t option | `Eof] Deferred.t =
  let handle tls raw =
    match tracing t @@ fun () -> Tls.Engine.handle_tls tls raw with
    | `Ok (state', `Response resp, `Data data) ->
        let state' =
          match state' with
          | `Ok tls -> `Active tls
          | `Eof -> `Eof
          | `Alert e -> `Error (Tls_alert e)
        in
        t.state <- state' ;
        (* XXX(dinosaure): at this stage, client would like to close. [tls], in
           this situation will send a CLOSE_NOTIFY but the client can already
           closed the connection.

           In this situation, try to write something will fail. [async] checks
           if a [fd] is closed (see [Fd.syscall]). If we follow the execution
           path, we should return an [Ok ()] instead to retrieve an exception.

           This comment is a response to mirleft#388 where [lwt] implementation
           needs to deal with this kind of leak. *)
        with_some (wr t) resp >>= fun () -> return (`Ok data)
    | `Fail (alert, `Response resp) ->
        t.state <- `Error (Tls_failure alert) ;
        wr t resp >>= fun () -> rd_react t
  in
  match t.state with
  | `Error _ -> return (`Ok None) (* do nothing, but still continue loop *)
  | `Eof ->
      if not (Fd.is_closed (Socket.fd t.socket)) then
        Socket.shutdown t.socket `Receive ;
      return `Eof
  | `Active _ -> (
      rd t t.recv_buf
      >>= fun r ->
      match (t.state, r) with
      | `Active _, `Eof ->
          t.state <- `Eof ;
          return `Eof
      | `Active tls, `Ok n -> handle tls (Cstruct.sub t.recv_buf 0 n)
      | `Error _, _ ->
          (* XXX(dinosaure): see [rd], when [Async_cstruct.reader_from_socket]
         returns [Error], we set [t.state] to be [`Error] (then, we get this
         case) AND we raise exception. *)
          return (`Ok None)
      | `Eof, _ ->
          (* XXX(dinosaure): [`Eof] on [t.state] is a non-sense, [rd] can set
         [t.state] only on [`Error]. So, if [t.state = `Eof], we already
         computed it before [rd]. *)
          assert false )

(* XXX(dinosaure): [rd] computes [t] and writes on [buf] decoded data. [linger]
   is an intermediate buffer to store only decoded data. *)
let rec rd t buf =
  let wr_out res =
    let rlen = Cstruct.len res in
    let n = min (Cstruct.len buf) rlen in
    Cstruct.blit res 0 buf 0 n ;
    t.linger <- (if n < rlen then Some (Cstruct.sub res n (rlen - n)) else None) ;
    return (`Ok n)
  in
  match t.linger with
  | Some res -> wr_out res
  | None -> (
      rd_react t
      >>= function
      | `Eof -> return `Eof
      (* XXX(dinosaure): [async] has a specific semantic where a [0] does not mean
       a closed socket. So we need to return [`Eof] or [`Ok n] to notice at the
       top if socket is closed or not. *)
      | `Ok None -> rd t buf
      | `Ok (Some res) -> wr_out res )

exception Tls_state_not_ready_to_send

let wrv t css =
  match t.state with
  | `Error _ -> return () (* exception leaks *)
  | `Eof ->
    t.state <- `Error Tls_close ; return ()
  | `Active tls -> (
    match tracing t @@ fun () -> Tls.Engine.send_application_data tls css with
    | Some (tls, data) ->
        t.state <- `Active tls ;
        wr t data
    | None ->
      t.state <- `Error Tls_state_not_ready_to_send ;
      return () )

let wr t cs = wrv t [cs]

(* XXX(dinosaure): this is a point that should particularly be protected from
   concurrent r/w. doing this before a [t] is returned is safe; redoing it
   during rekeying is not, as the API client already sees the [t] and can
   mistakenly interleave writes while this is in progress. *)
let rec drain_handshake t =
  let to_linger t mcs =
    match (mcs, t.linger) with
    | None, _ -> ()
    | scs, None -> t.linger <- scs
    | Some cs, Some linger -> t.linger <- Some (Cstruct.append linger cs)
  in
  match t.state with
  | `Error _ -> return t
  | `Eof -> return t
  | `Active tls -> (
      if not (Tls.Engine.handshake_in_progress tls) then return t
      else
        rd_react t
        >>= function
        | `Eof ->
          t.state <- `Error Tls_close ;
          return t
        | `Ok cs -> to_linger t cs ; drain_handshake t )

exception Tls_can't_renegotiate

let reneg ?authenticator ?acceptable_cas ?cert ?(drop = true) t =
  match t.state with
  | `Error _ -> return ()
  | `Eof ->
    t.state <- `Error Tls_close ; return ()
  | `Active tls -> (
    match
      tracing t
      @@ fun () -> Tls.Engine.reneg ?authenticator ?acceptable_cas ?cert tls
    with
    | None ->
      t.state <- `Error Tls_can't_renegotiate ;
      return ()
    | Some (tls', buf) ->
        if drop then t.linger <- None ;
        t.state <- `Active tls' ;
        wr t buf
        >>= fun () ->
        drain_handshake t
        >>= fun _t ->
        assert (Core.phys_equal t _t) ;
        return () )

let close t =
  match t.state with
  | `Active tls ->
      let _, buf = tracing t @@ fun () -> Tls.Engine.send_close_notify tls in
      t.state <- `Eof ;
      wr t buf
  | _ -> return ()

let close ~error t =
  Monitor.try_with ~name:"close" (fun () -> close t)
  >>= (function Ok () -> return () | Error exn -> error exn)
  (* XXX(dinosaure): if [Fd.close] raises an exception, it should be catched by
     user - not by me. *)
  >>| fun () ->
  if not (Fd.is_closed (Socket.fd t.socket)) then
    Deferred.don't_wait_for (Fd.close (Socket.fd t.socket))

let server_of_socket ?tracer config socket =
  drain_handshake
    {state= `Active (Tls.Engine.server config); socket; recv_buf= Cstruct.create 4096; linger= None; tracer}

let client_of_socket ?tracer config ?host socket =
  let config' =
    match host with None -> config | Some host -> Tls.Config.peer config host
  in
  let tls, init = Tls.Engine.client config' in
  let t = {state= `Active tls; socket; recv_buf= Cstruct.create 4096; linger= None; tracer} in
  wr t init >>= fun () -> drain_handshake t

exception Tls_socket_closed

let accept ?tracer config socket =
  Socket.accept socket
  >>= function
  | `Socket_closed -> raise Tls_socket_closed
  | `Ok (socket', addr) -> (
      Monitor.try_with ~name:"handshake" (fun () ->
          server_of_socket ?tracer config socket' >>| fun t -> (t, addr) )
      >>= function
      | Ok v -> return v
      | Error exn ->
          Socket.shutdown socket' `Both ;
          raise exn )

let connect ?tracer config socket addr =
  Monitor.try_with ~name:"connect" (fun () ->
      Socket.connect socket addr
      >>= fun socket' -> client_of_socket ?tracer config socket' )
  (* TODO: handle host. *)
  >>= function
  | Ok v -> return v
  | Error exn ->
      Socket.shutdown socket `Both ;
      raise exn

let read t buffer off len = rd t (Cstruct.of_bigarray ~off ~len buffer)

let write t buffer off len = wr t (Cstruct.of_bigarray ~off ~len buffer)

let pipe ~error t =
  let b_reader = Cstruct.create 0x8000 in
  let rec f_reader writer =
    rd t b_reader
    >>= function
    | `Ok len ->
        Pipe.write writer (Cstruct.to_string (Cstruct.sub b_reader 0 len))
        >>= fun () -> f_reader writer
    | `Eof ->
        (* XXX(dinosaure): if we don't do that, we have an infinite loop. *)
        Pipe.close writer ; return ()
  in
  let rec f_writer reader =
    Pipe.read reader
    >>= function
    | `Ok s -> wr t (Cstruct.of_string s) >>= fun () -> f_writer reader
    | `Eof -> close ~error t
  in
  (* XXX(dinosaure): may be we need to close [reader]. *)
  ( Pipe.create_reader ~close_on_exception:false f_reader
  , Pipe.create_writer f_writer )

let reader_and_writer ~error t =
  let pr, pw = pipe ~error t in
  let info = Info.create "tls" t Sexplib.Conv.sexp_of_opaque in
  Reader.of_pipe info pr
  >>= fun reader ->
  Writer.of_pipe info pw
  >>= fun (writer, `Closed_and_flushed_downstream closed) ->
  return (reader, writer, closed)

let epoch t =
  match t.state with
  | `Active tls -> (
    match Tls.Engine.epoch tls with
    | `InitialEpoch -> assert false (* can never occur. *)
    | `Epoch data -> `Ok data )
  | `Eof | `Error _ -> `Error

(* TODO: replace by an async filler. *)
let () = ignore @@ Nocrypto_entropy_async.initialize ()
