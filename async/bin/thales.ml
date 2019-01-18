let invalid_arg fmt = Fmt.kstrf (fun e -> invalid_arg e) fmt

let ( <.> ) f g x = f (g x)

module U = Unix

type cipher =
  [ `AES_128_CBC_SHA
  | `AES_128_CBC_SHA256
  | `AES_128_CCM
  | `AES_128_GCM_SHA256
  | `AES_256_CBC_SHA
  | `AES_256_CBC_SHA256
  | `AES_256_CCM
  | `AES_256_GCM_SHA384
  | `_3DES_EDE_CBC_SHA
  | `RC4_128_MD5
  | `RC4_128_SHA ]

let ciphers =
  [ ("aes-128-cbc-hmac-sha1", `AES_128_CBC_SHA)
  ; ("aes-128-cbc-hmac-sha256", `AES_128_CBC_SHA256)
  ; ("aes-128-ccm", `AES_128_CCM)
  ; ("aes-128-gcm-hmac-sha256", `AES_128_GCM_SHA256)
  ; ("aes-256-cbc-hmac-sha1", `AES_256_CBC_SHA)
  ; ("aes-256-cbc-hmac-sha256", `AES_256_CBC_SHA256)
  ; ("aes-256-ccm", `AES_256_CCM)
  ; ("aes-256-gcm-hmac-sha384", `AES_256_GCM_SHA384)
  ; ("3des-ede-cbc-hmac-sha1", `_3DES_EDE_CBC_SHA)
  ; ("rc4-128-hmac-md5", `RC4_128_MD5)
  ; ("rc4-128-hmac-sha1", `RC4_128_SHA) ]

let cipher_to_string cipher =
  List.find (fun (_, x) -> x = cipher) ciphers |> fst

let cipher_of_string s =
  try List.assoc s ciphers with _ -> invalid_arg "Invalid cipher: %s" s

let cipher_pp ppf = Fmt.string ppf <.> cipher_to_string

type algorithm = [`RSA | `DHE_RSA]

let algorithms = [("rsa", `RSA); ("dhe-rsa", `DHE_RSA)]

let algorithm_to_string algorithm =
  List.find (fun (_, x) -> x = algorithm) algorithms |> fst

let algorithm_of_string s =
  try List.assoc s algorithms with _ -> invalid_arg "Invalid algorithm: %s" s

let algorithm_pp ppf = Fmt.string ppf <.> algorithm_to_string

let ciphersuite algorithm cipher : Tls.Ciphersuite.ciphersuite =
  match (cipher, algorithm) with
  | `AES_128_CBC_SHA, `RSA -> `TLS_RSA_WITH_AES_128_CBC_SHA
  | `AES_128_CBC_SHA256, `RSA -> `TLS_RSA_WITH_AES_128_CBC_SHA256
  | `AES_128_CCM, `RSA -> `TLS_RSA_WITH_AES_128_CCM
  | `AES_128_GCM_SHA256, `RSA -> `TLS_RSA_WITH_AES_128_GCM_SHA256
  | `AES_256_CBC_SHA, `RSA -> `TLS_RSA_WITH_AES_256_CBC_SHA
  | `AES_256_CBC_SHA256, `RSA -> `TLS_RSA_WITH_AES_256_CBC_SHA256
  | `AES_256_CCM, `RSA -> `TLS_RSA_WITH_AES_256_CCM
  | `AES_256_GCM_SHA384, `RSA -> `TLS_RSA_WITH_AES_256_GCM_SHA384
  | `_3DES_EDE_CBC_SHA, `RSA -> `TLS_RSA_WITH_3DES_EDE_CBC_SHA
  | `RC4_128_MD5, `RSA -> `TLS_RSA_WITH_RC4_128_MD5
  | `RC4_128_SHA, `RSA -> `TLS_RSA_WITH_RC4_128_SHA
  | `AES_128_CBC_SHA, `DHE_RSA -> `TLS_DHE_RSA_WITH_AES_128_CBC_SHA
  | `AES_128_CBC_SHA256, `DHE_RSA -> `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
  | `AES_128_CCM, `DHE_RSA -> `TLS_DHE_RSA_WITH_AES_128_CCM
  | `AES_128_GCM_SHA256, `DHE_RSA -> `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
  | `AES_256_CBC_SHA, `DHE_RSA -> `TLS_DHE_RSA_WITH_AES_256_CBC_SHA
  | `AES_256_CBC_SHA256, `DHE_RSA -> `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
  | `AES_256_CCM, `DHE_RSA -> `TLS_DHE_RSA_WITH_AES_256_CCM
  | `AES_256_GCM_SHA384, `DHE_RSA -> `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
  | `_3DES_EDE_CBC_SHA, `DHE_RSA -> `TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
  | `RC4_128_MD5, `DHE_RSA | `RC4_128_SHA, `DHE_RSA ->
      invalid_arg "Ciphersuite unavailable"

let split_ciphersuite = function
  | `TLS_RSA_WITH_AES_128_CBC_SHA -> (`RSA, `AES_128_CBC_SHA)
  | `TLS_RSA_WITH_AES_128_CBC_SHA256 -> (`RSA, `AES_128_CBC_SHA256)
  | `TLS_RSA_WITH_AES_128_CCM -> (`RSA, `AES_128_CCM)
  | `TLS_RSA_WITH_AES_128_GCM_SHA256 -> (`RSA, `AES_128_GCM_SHA256)
  | `TLS_RSA_WITH_AES_256_CBC_SHA -> (`RSA, `AES_256_CBC_SHA)
  | `TLS_RSA_WITH_AES_256_CBC_SHA256 -> (`RSA, `AES_256_CBC_SHA256)
  | `TLS_RSA_WITH_AES_256_CCM -> (`RSA, `AES_256_CCM)
  | `TLS_RSA_WITH_AES_256_GCM_SHA384 -> (`RSA, `AES_256_GCM_SHA384)
  | `TLS_RSA_WITH_RC4_128_MD5 -> (`RSA, `RC4_128_MD5)
  | `TLS_RSA_WITH_RC4_128_SHA -> (`RSA, `RC4_128_SHA)
  | `TLS_RSA_WITH_3DES_EDE_CBC_SHA -> (`RSA, `_3DES_EDE_CBC_SHA)
  | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA -> (`RSA, `AES_128_CBC_SHA)
  | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 -> (`RSA, `AES_128_CBC_SHA256)
  | `TLS_DHE_RSA_WITH_AES_128_CCM -> (`RSA, `AES_128_CCM)
  | `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 -> (`RSA, `AES_128_GCM_SHA256)
  | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA -> (`RSA, `AES_256_CBC_SHA)
  | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 -> (`RSA, `AES_256_CBC_SHA256)
  | `TLS_DHE_RSA_WITH_AES_256_CCM -> (`RSA, `AES_256_CCM)
  | `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 -> (`RSA, `AES_256_GCM_SHA384)
  | `TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA -> (`RSA, `_3DES_EDE_CBC_SHA)

let versions =
  [ ("1.0", Tls.Core.TLS_1_0)
  ; ("1.1", Tls.Core.TLS_1_1)
  ; ("1.2", Tls.Core.TLS_1_2) ]

let hashes =
  [ ("md5", `MD5)
  ; ("sha1", `SHA1)
  ; ("sha224", `SHA224)
  ; ("sha256", `SHA256)
  ; ("sha384", `SHA384)
  ; ("sha512", `SHA512) ]

let hash_to_string hash = List.find (fun (_, x) -> x = hash) hashes |> fst

let hash_of_string s =
  try List.assoc s hashes with _ -> invalid_arg "Invalid hash: %s" s

let hash_pp ppf = Fmt.string ppf <.> hash_to_string

type authenticator =
  [`Ca_file of Fpath.t | `Ca_dir of Fpath.t | `No_authentication]

type own_cert =
  [ `Multiple of (Fpath.t * Fpath.t) list
  | `Multiple_default of (Fpath.t * Fpath.t) * (Fpath.t * Fpath.t) list
  | `Single of Fpath.t * Fpath.t ]

exception Jump of Core.Error.t

let to_own_cert own_cert :
    Tls.Config.own_cert Core.Or_error.t Async.Deferred.t =
  let list_of_result_to_result_of_list lst =
    try
      Ok (List.map (function Error err -> raise (Jump err) | Ok v -> v) lst)
    with Jump err -> Error err
  in
  let open Async in
  match own_cert with
  | `Multiple_default ((default_cert, default_priv_key), chain) ->
      X509_async.private_of_pems ~cert:default_cert ~priv_key:default_priv_key
      >>= fun default ->
      Deferred.List.map
        ~f:(fun (cert, priv_key) -> X509_async.private_of_pems ~cert ~priv_key)
        chain
      >>| fun chain ->
      Core.Or_error.(
        list_of_result_to_result_of_list chain
        >>= fun chain ->
        default >>| fun default -> `Multiple_default (default, chain))
  | `Multiple [(cert, priv_key)] | `Single (cert, priv_key) -> (
      X509_async.private_of_pems ~cert ~priv_key
      >>| function Ok v -> Ok (`Single v) | Error _ as err -> err )
  | `Multiple chain ->
      Deferred.List.map
        ~f:(fun (cert, priv_key) -> X509_async.private_of_pems ~cert ~priv_key)
        chain
      >>| fun chain ->
      Core.Or_error.(
        list_of_result_to_result_of_list chain >>| fun chain -> `Multiple chain)

let on_some f = function
  | Some x -> Async.(f x >>| fun x -> Some x)
  | None -> Async.return None

let tracer sexp = Fmt.pr "S> %a.\n%!" Sexplib.Sexp.pp sexp

let handle callback t peer =
  let open Async in
  let error exn = Fmt.pr "> return an error: %s." (Printexc.to_string exn); return () in
  let process () =
    Tls_async.reader_and_writer ~error t
    >>> fun (rd, wr, cl) -> callback rd wr cl peer
  in
  let monitor = Monitor.create ~name:"clients" () in
  Scheduler.within ~monitor process ;
  Monitor.detach_and_iter_errors monitor ~f:(function
    | Tls_async.Tls_alert e ->
        Fmt.epr "!> %s.\n%!" (Tls.Packet.alert_type_to_string e)
    | Tls_async.Tls_failure e ->
        Fmt.epr "!> %s.\n%!" (Tls.Engine.string_of_failure e)
    | Tls_async.Tls_close -> Fmt.epr "!> tls connection close.\n%!"
    | Unix.Unix_error (e, f, p) ->
        Fmt.epr "!> (%s, %s, %s).\n%!" (U.error_message e) f p
    | exn -> Fmt.epr "!> %s.\n%!" (Core.Exn.to_string exn) )

let run host port config =
  let open Async in
  let callback rd wr cl _peer =
    let rec go () =
      Reader.read_line rd
      >>= function
      | `Ok line -> Fmt.pr "> %s.\n%!" line; Writer.write_line wr line ; go ()
      | `Eof -> Fmt.pr "> connection closed.\n%!"; Writer.close wr >>= fun () -> cl
    in
    go () >>= fun () -> return ()
  in
  Unix.Inet_addr.of_string_or_getbyname host
  >>= fun host ->
  let socket = Socket.create Socket.Type.tcp in
  let socket =
    Socket.bind_inet ~reuseaddr:true socket
      (Socket.Address.Inet.create host ~port)
  in
  let socket = Socket.listen socket in
  Fmt.pr "=> Socket binded.\n%!" ;
  let rec loop socket =
    Tls_async.accept config socket
    >>= function
    | Ok (t, peer) ->
        handle
          (fun rd wr cl peer -> callback rd wr cl peer >>> fun () -> ())
          t peer ;
        loop socket
    | Error err ->
        Fmt.epr "!> %a.\n%!" Core.Error.pp err ;
        loop socket
  in
  loop socket >>= fun () -> return (`Ok ())

let main host port reneg certificates authenticator ciphers hashes =
  let open Async in
  X509_async.authenticator authenticator
  >>= fun authenticator ->
  on_some to_own_cert certificates
  >>= fun certificates ->
  match (authenticator, certificates) with
  | Error err, _ | _, Some (Error err) ->
      return (`Error (false, err))
  | Ok authenticator, Some (Ok certificates) ->
      let config =
        Tls.Config.server ?ciphers ?hashes ~reneg ~certificates ~authenticator
          ()
      in
      run host port config
  | Ok authenticator, None ->
      let config =
        Tls.Config.server ?ciphers ?hashes ~reneg ~authenticator ()
      in
      run host port config

let check host port reneg certificates ca_file ca_path ciphers hashes =
  let authenticator =
    match (ca_file, ca_path) with
    | Some ca_file, None -> `Ca_file ca_file
    | None, Some ca_path -> `Ca_dir ca_path
    | None, None -> `No_authentication
    | Some _, Some _ ->
        `Error (true, Core.Error.of_string "Impossible to load both CA file and CA directory.")
  in
  match authenticator with
  | `Error _ as err -> err
  | #authenticator as authenticator -> (
    match
      Async.Thread_safe.block_on_async (fun () ->
          main host port reneg certificates authenticator ciphers hashes )
    with
    | Ok v -> v
    | Error exn ->
        `Error
          ( false
          , Core.Error.of_exn ~backtrace:(`This "Got an exception during executation") exn) )

open Cmdliner

let ffile =
  let parse path =
    if Sys.file_exists path then Fpath.of_string path
    else Rresult.R.error_msgf "File %s does not exist" path
  in
  let pp = Fpath.pp in
  Arg.conv ~docv:"<file>" (parse, pp)

let path =
  let parse path =
    if Sys.is_directory path then Fpath.of_string path
    else Rresult.R.error_msgf "Path %s is not a directory" path
  in
  let pp = Fpath.pp in
  Arg.conv ~docv:"<directory>" (parse, pp)

let ca_file =
  let doc = "PEM format file of CA's" in
  Arg.(value & opt (some ffile) None & info ["ca-file"] ~doc)

let ca_path =
  let doc = "PEM format directory of CA's" in
  Arg.(value & opt (some path) None & info ["ca-path"] ~doc)

let cipher =
  let parse s =
    try Rresult.R.ok (cipher_of_string s) with Invalid_argument err ->
      Rresult.R.error_msg err
  in
  let pp = cipher_pp in
  Arg.conv (parse, pp) ~docv:"<cipher>"

let algorithm =
  let parse s =
    try Rresult.R.ok (algorithm_of_string s) with Invalid_argument err ->
      Rresult.R.error_msg err
  in
  let pp = algorithm_pp in
  Arg.conv (parse, pp) ~docv:"<algorithm>"

let ciphersuite =
  let parse s =
    match Astring.String.cut ~sep:":" s with
    | None -> Rresult.R.error_msgf "Invalid format of ciphersuite: %s" s
    | Some (a, c) -> (
      match (Arg.conv_parser algorithm a, Arg.conv_parser cipher c) with
      | (Error _ as err), _ | _, (Error _ as err) -> err
      | Ok a, Ok c -> (
        try Rresult.R.ok (ciphersuite a c) with Invalid_argument err ->
          Rresult.R.error_msg err ) )
  in
  let pp =
    Fmt.using split_ciphersuite
      (Fmt.pair ~sep:(Fmt.const Fmt.string ":") algorithm_pp cipher_pp)
  in
  Arg.conv ~docv:"<algorithm>:<cipher>" (parse, pp)

let hash : Nocrypto.Hash.hash Arg.conv =
  let parse s =
    try Rresult.R.ok (hash_of_string s) with Invalid_argument err ->
      Rresult.R.error_msg err
  in
  let pp = hash_pp in
  Arg.conv ~docv:"<hash>" (parse, pp)

let certchain =
  let parse s =
    match Astring.String.cut ~sep:":" s with
    | Some (cert, priv_key) ->
        if Sys.file_exists cert && Sys.file_exists priv_key then
          Rresult.R.(
            Fpath.of_string cert
            >>= fun cert ->
            Fpath.of_string priv_key >>= fun priv_key -> return (cert, priv_key))
        else
          Rresult.R.error_msgf
            "Certificate file or private key file don't exist: %s or %s" cert
            priv_key
    | None -> Rresult.R.error_msgf "Invalid format of certchain: %s" s
  in
  let pp = Fmt.pair ~sep:(Fmt.const Fmt.string ":") Fpath.pp Fpath.pp in
  Arg.conv ~docv:"<certificate>:<private-key>" (parse, pp)

let own_cert =
  let pp_certchain = Arg.conv_printer certchain in
  let parse_certchain = Arg.conv_parser certchain in
  let parse s =
    let rest_parse = function
      | [] -> Rresult.R.ok (`Multiple [])
      | [v] -> Rresult.R.(parse_certchain v >>| fun v -> `Single v)
      | own_cert ->
          let own_cert =
            List.map parse_certchain own_cert
            |> List.fold_left
                 (fun acc -> function Ok v -> v :: acc | Error _ -> acc)
                 []
          in
          Rresult.R.ok (`Multiple own_cert)
    in
    match Astring.String.cut ~sep:"!" s with
    | None -> (
      try rest_parse (Astring.String.cuts ~sep:"," s) with _ ->
        Rresult.R.error_msgf "Invalid format of own-cert: %s" s )
    | Some (default, rest) -> (
        let open Rresult.R in
        parse_certchain default
        >>= fun default ->
        ( try rest_parse (Astring.String.cuts ~sep:"," rest) with _ ->
            Rresult.R.error_msgf "Invalid format of own-cert: %s" rest )
        >>| function
        | `Single rest -> `Multiple_default (default, [rest])
        | `Multiple rest -> `Multiple_default (default, rest) )
  in
  let pp ppf = function
    | `Multiple lst ->
        Fmt.pf ppf "(`Multiple %a)"
          Fmt.(list ~sep:(const string ",") pp_certchain)
          lst
    | `Single v -> Fmt.pf ppf "(`Single %a)" pp_certchain v
    | `Multiple_default (v, lst) ->
        Fmt.pf ppf "(`Multiple_default %a)"
          Fmt.(
            pair ~sep:(const string "!") pp_certchain
              (list ~sep:(const string ",") pp_certchain))
          (v, lst)
  in
  Arg.conv (parse, pp)

let ciphers =
  let doc = "Ciphers." in
  Arg.(value & opt (some (list ciphersuite)) None & info ["ciphers"] ~doc)

let hashes =
  let doc = "Hashes." in
  Arg.(value & opt (some (list hash)) None & info ["hashes"] ~doc)

let own_cert =
  let doc = "Read a certificate chain." in
  Arg.(value & opt (some own_cert) None & info ["chain"] ~doc)

let with_default =
  let doc = "First element of certificate chain as default." in
  Arg.(value & flag & info ["with-default"] ~doc)

let reneg =
  let doc = "Renegotation." in
  Arg.(value & flag & info ["reneg"] ~doc)

let host =
  let doc = "Hostname." in
  Arg.(value & opt string "localhost" & info ["h"; "host"] ~doc)

let port =
  let doc = "Port." in
  Arg.(value & opt int 43 & info ["p"; "port"] ~doc)

let ret_with_core_error = function
  | `Ok _ as v -> v
  | `Help _ as v -> v
  | `Error (r, exn) -> `Error (r, Core.Error.to_string_hum exn)

let cmd =
  let doc = "Example to use ocaml-tls with async." in
  let exits = Term.default_exits in
  ( Term.(
      ret
        (app (pure ret_with_core_error)
           (const check $ host $ port $ reneg $ own_cert $ ca_file $ ca_path $ ciphers $ hashes)))
  , Term.info "thales" ~doc ~exits )

let () = Term.(exit @@ eval cmd)
