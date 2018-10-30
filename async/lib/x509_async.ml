open Core
open Async

type priv = X509.t list * Nocrypto.Rsa.priv

type authenticator = X509.Authenticator.a

let ( <.> ) f g x = f (g x)

let load_dir path =
  Sys.ls_dir (Fpath.to_string path) >>| List.map ~f:Fpath.(( / ) path)

let load_file path =
  (* XXX(dinosaure): why [Monitor]? It seems the safer way to load a file
     without exception leaks. *)
  Monitor.try_with ~run:`Now (fun () ->
      Reader.file_contents (Fpath.to_string path) >>| Cstruct.of_string )
  >>= function
  | Ok _ as v -> return v
  | Error exn ->
      return
        (Rresult.R.error_msgf "Got an error when we load %a: %s" Fpath.pp path
           (Exn.to_string exn))

let private_of_pems ~cert ~priv_key =
  let open X509.Encoding.Pem in
  load_file cert
  >>| Rresult.R.map Certificate.of_pem_cstruct
  >>= fun certs ->
  load_file priv_key
  >>| Rresult.R.map Private_key.of_pem_cstruct1
  >>= fun pk ->
  match (certs, pk) with
  | Ok certs, Ok (`RSA pk) -> return (Rresult.R.ok (certs, pk))
  | (Error _ as err), Ok _ -> return err
  | Ok _, (Error _ as err) -> return err
  | Error (`Msg err0), Error (`Msg err1) -> assert false

(* end of the world! *)

let certs_of_pem path =
  load_file path >>| Rresult.R.map X509.Encoding.Pem.Certificate.of_pem_cstruct

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
  let now = Ptime_clock.now () in
  let of_meth meth = X509.Authenticator.chain_of_trust ~time:now meth
  and dotted_hex_to_cs =
    Nocrypto.Uncommon.Cs.of_hex
    <.> String.map ~f:(function ':' -> ' ' | x -> x)
  and fingerprint hash fingerprints =
    X509.Authenticator.server_key_fingerprint ~time:now ~hash ~fingerprints
  in
  match meth with
  | `Ca_file path -> certs_of_pem path >>| Rresult.R.map of_meth
  | `Ca_dir path -> certs_of_pem_dir path >>| of_meth >>| Rresult.R.ok
  | `Key_fingerprints (hash, fps) ->
      return (Rresult.R.ok (fingerprint hash fps))
  | `Hex_key_fingerprints (hash, fps) ->
      let fps = List.map ~f:(fun (n, v) -> (n, dotted_hex_to_cs v)) fps in
      return (Rresult.R.ok (fingerprint hash fps))
  | `No_authentication -> return (Rresult.R.ok X509.Authenticator.null)
