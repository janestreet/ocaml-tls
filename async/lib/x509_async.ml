let ( <.> ) f g x = f (g x)

open Core
open Async

type priv = X509.t list * Nocrypto.Rsa.priv

type authenticator = X509.Authenticator.a

let load_dir path =
  Sys.ls_dir (Fpath.to_string path) >>| List.map ~f:Fpath.(( / ) path)

let load_file path =
  Monitor.try_with ~run:`Now (fun () ->
      Reader.file_contents (Fpath.to_string path) >>| Cstruct.of_string )
  >>| function
  | Ok v -> Ok v
  | Error exn ->
      (* TODO: replace by [Or_error]. *)
      error_msgf "Got an error when we load %a: %s" Fpath.pp path
        (Exn.to_string exn)

let private_of_pems ~cert ~priv_key =
  let open X509.Encoding.Pem in
  load_file cert
  >>| Result.map ~f:Certificate.of_pem_cstruct
  >>= fun certs ->
  load_file priv_key
  >>| Result.map ~f:Private_key.of_pem_cstruct1
  >>= fun pk ->
  match (certs, pk) with
  | Ok certs, Ok (`RSA pk) -> return (Ok (certs, pk))
  | (Error _ as err), Ok _ -> return err
  | Ok _, (Error _ as err) -> return err
  | Error (`Msg _err0), Error (`Msg _err1) ->
      (* TODO: combine errors. *)
      assert false

let certs_of_pem path =
  load_file path >>| Result.map ~f:X509.Encoding.Pem.Certificate.of_pem_cstruct

let certs_of_pem_dir ?(ext = "crt") path =
  load_dir path
  >>| List.filter ~f:(Fpath.has_ext ext)
  >>= Deferred.List.concat_map ~how:`Parallel ~f:(fun path ->
          certs_of_pem path
          >>| function
          | Ok certs -> certs
          | Error (`Msg err) ->
              Fmt.epr "Silently got an error when we tried to load %a: %s"
                Fpath.pp path err ;
              [] )

let authenticator meth =
  let time = Synchronous_time_source.wall_clock () in
  let now =
    Synchronous_time_source.now time
    |> Time_ns.to_span_since_epoch |> Time_ns.Span.to_int_sec
    |> Ptime.Span.of_int_s |> Ptime.of_span
    |> fun opt -> Option.value_exn ~message:"Invalid time value" opt
  in
  let of_meth meth = X509.Authenticator.chain_of_trust ~time:now meth
  and dotted_hex_to_cs =
    Nocrypto.Uncommon.Cs.of_hex
    <.> String.map ~f:(function ':' -> ' ' | x -> x)
  and fingerprint hash fingerprints =
    X509.Authenticator.server_key_fingerprint ~time:now ~hash ~fingerprints
  in
  match meth with
  | `Ca_file path -> certs_of_pem path >>| Result.map ~f:of_meth
  | `Ca_dir path -> certs_of_pem_dir path >>| of_meth >>| Result.return
  | `Key_fingerprints (hash, fps) -> return (Ok (fingerprint hash fps))
  | `Hex_key_fingerprints (hash, fps) ->
      let fps = List.map ~f:(fun (n, v) -> (n, dotted_hex_to_cs v)) fps in
      return (Ok (fingerprint hash fps))
  | `No_authentication -> return (Ok X509.Authenticator.null)
