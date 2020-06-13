-module(wallet_cli_main).

-export([main/1]).
-export([cmd_create_basic/1, cmd_create_basic/2,
         cmd_create_sharded/1, cmd_create_sharded/2]).

-define(PBKDF2_DEFAULT_ITERATIONS, 100000).
-define(SHARDED_DEFAULT_SHARDS, 5).
-define(SHARDED_DEFAULT_REQUIRED_SHARDS, 3).

basic_key_opt_specs() ->
    [
     {output_file, $o, "output", {string, "wallet.key"}, "Output file to store the key in"},
     {force, undefined, "force", undefined, "Overwrite an existing file"},
     {iterations,  $i, "iterations", {integer, ?PBKDF2_DEFAULT_ITERATIONS}, "Number of PBKDF2 iterations"}
    ].

sharded_key_opt_specs() ->
    basic_key_opt_specs() ++
        [
         {shards, $n, "shards", {integer, ?SHARDED_DEFAULT_SHARDS}, "Number of shards to break the key into"},
         {required_shards, $k, "required-shards", {integer, ?SHARDED_DEFAULT_REQUIRED_SHARDS},
          "Number of shards required to recover the key"}
        ].

help_opt_specs() ->
    [
     {help,        $h,        "help",    undefined,               "Print this help text"}
    ].


file_opt_specs() ->
    [
     {file, $f, "file", {string, "wallet.key"}, "Wallet file to load"}
     ].


main(["create", "basic" | Args]) ->
    AppDir = filename:dirname(filename:dirname(code:where_is_file("wallet"))),
    os:putenv("NIF_PATH", AppDir),

    OptSpecs = basic_key_opt_specs() ++ help_opt_specs(),
    handle_cmd(OptSpecs, "create basic", Args, fun cmd_create_config/1, fun cmd_create_basic/1);
main(["create", "sharded" | Args]) ->
    AppDir = filename:dirname(filename:dirname(code:where_is_file("wallet"))),
    os:putenv("NIF_PATH", AppDir),

    OptSpecs = sharded_key_opt_specs() ++ help_opt_specs(),
    handle_cmd(OptSpecs, "create sharded", Args, fun cmd_create_config/1, fun cmd_create_sharded/1);
main(["create" | _Args]) ->
    OptSpecs =
        [
         {basic,  undefined, undefined, undefined, "Create a basic wallet"},
         {sharded,undefined, undefined, undefined, "Create a sharded wallet"}
        ],
    usage("create", OptSpecs);
main(["convert", "basic" | Args]) ->
    AppDir = filename:dirname(filename:dirname(code:where_is_file("wallet"))),
    os:putenv("NIF_PATH", AppDir),

    OptSpecs = file_opt_specs() ++ basic_key_opt_specs() ++ help_opt_specs(),
    handle_cmd(OptSpecs, "convert basic", Args, fun cmd_convert_config/1, fun cmd_convert_basic/1);
main(["convert", "sharded" | Args]) ->
    AppDir = filename:dirname(filename:dirname(code:where_is_file("wallet"))),
    os:putenv("NIF_PATH", AppDir),

    OptSpecs = file_opt_specs() ++ sharded_key_opt_specs() ++ help_opt_specs(),
    handle_cmd(OptSpecs, "convert sharded", Args, fun cmd_convert_config/1, fun cmd_convert_sharded/1);
main(["convert" | _Args]) ->
    OptSpecs =
        [
         {basic,  undefined, undefined, undefined, "Convert to the latest version of a basic wallet"},
         {sharded,undefined, undefined, undefined, "Convert to the latest version of a sharded wallet"}
        ],
    usage("convert", OptSpecs);
main(["info"=Cmd | Args]) ->
    OptSpecs = file_opt_specs() ++ help_opt_specs(),
    handle_cmd(OptSpecs, Cmd, Args, fun cmd_info/1);
main(["verify"=Cmd | Args]) ->
    AppDir = filename:dirname(filename:dirname(code:where_is_file("wallet"))),
    os:putenv("NIF_PATH", AppDir),

    OptSpecs = file_opt_specs() ++ help_opt_specs(),
    handle_cmd(OptSpecs, Cmd, Args, fun cmd_verify_config/1, fun cmd_verify/1);
main(["balance"=Cmd | Args]) ->
    OptSpecs =
        [
         {key,  $k, "key",  string,                 "Public key to get balance for"}
         ] ++ file_opt_specs() ++ help_opt_specs(),
    handle_cmd(OptSpecs, Cmd, Args, fun cmd_balance/1);
main(["version"=Cmd | Args]) ->
    OptSpecs = help_opt_specs(),
    handle_cmd(OptSpecs, Cmd, Args, fun cmd_version/1);
main(_) ->
    OptSpecs =
        [
         {version,undefined, undefined, undefined, "Displays the version of this application"},
         {create, undefined, undefined, undefined, "Create a new encrypted wallet"},
         {convert,undefined, undefined, undefined, "Convert a wallet to a newer or different format"},
         {verify, undefined, undefined, undefined, "Verify an ecnrypted wallet"},
         {info,   undefined, undefined, undefined, "Get public wallet address"},
         {balance,undefined, undefined, undefined, "Get balance for a wallet or a given address"}
        ],
    usage("", OptSpecs).


-define(BASIC_KEY_V1,   16#0000).
-define(BASIC_KEY_V2,   16#0001).
-define(SHARDED_KEY_V1, 16#0100).
-define(SHARDED_KEY_V2, 16#0101).
-type basic_key_version() :: ?BASIC_KEY_V1 | ?BASIC_KEY_V2.
-type sharded_key_version() :: ?SHARDED_KEY_V1 | ?SHARDED_KEY_V2.
-type key_map() :: #{ secret => libp2p_crypto:privkey(), public => libp2p_crypto:pubkey()}.
-record(basic_key, {
                    version :: basic_key_version(),
                    keymap :: key_map(),
                    iterations :: pos_integer()
                   }).
-record(enc_basic_key, {
                        version :: basic_key_version(),
                        pubkey_bin :: libp2p_crypto:pubkey_bin(),
                        iv :: binary(),
                        salt:: binary(),
                        iterations :: pos_integer(),
                        tag :: binary(),
                        encrypted :: binary()
                       }).
-record(sharded_key, {
                      version :: sharded_key_version(),
                      keymap :: key_map(),
                      iterations :: pos_integer(),
                      key_shares :: pos_integer(),
                      recovery_threshold :: pos_integer()
                     }).
-record(enc_sharded_key, {
                          version :: sharded_key_version(),
                          key_shares :: pos_integer(),
                          recovery_threshold :: pos_integer(),
                          key_share :: binary(),
                          pubkey_bin :: libp2p_crypto:pubkey_bin(),
                          iv :: binary(),
                          salt:: binary(),
                          iterations :: pos_integer(),
                          tag :: binary(),
                          encrypted :: binary()
                         }).
-type key() :: #basic_key{} | #sharded_key{}.
-type enc_key() :: #enc_basic_key{} | #enc_sharded_key{}.

%%
%% version
%%

cmd_version(_) ->
    application:load(wallet),
    Version = case lists:keyfind(wallet, 1, application:loaded_applications()) of
                  false -> "unknown";
                  {_, _, V} -> V
              end,
    io:format("Version: ~s~n", [Version]).

%%
%% create
%%

cmd_create_config(Opts) ->
    Password = string:strip(string:strip(io:get_line("Password: "), right, $\n), right, $\r),
    PasswordVerify = string:strip(string:strip(io:get_line("Verify Password: "), right, $\n), right, $\r),
    case Password == PasswordVerify of
        false ->
            io:format("Passwords do not match~n"),
            halt(1);
        true ->
            {ok, [{password, Password} | Opts]}
    end.

cmd_create_basic(Opts) ->
    cmd_create_basic(Opts, libp2p_crypto:generate_keys(ed25519)).

cmd_create_basic(Opts, Keys = #{ public := PubKey }) ->
    Password = proplists:get_value(password, Opts),
    Iterations = proplists:get_value(iterations, Opts, ?PBKDF2_DEFAULT_ITERATIONS),
    Key = #basic_key{
             version = ?BASIC_KEY_V2,
             keymap = Keys,
             iterations = Iterations
            },
    [EncKey] = encrypt_key(Key, Password),
    Bin = enc_key_to_bin(EncKey),
    OutFile = proplists:get_value(output_file, Opts),
    case write_output_file(OutFile, Bin, Opts) of
        {error, file_exists} ->
            io:format("File ~p already exists~n", [OutFile]),
            halt(1);
        ok ->
            io:format("Address: ~s~nFile: ~s~n",
                      [libp2p_crypto:pubkey_to_b58(PubKey), OutFile])
    end.

cmd_create_sharded(Opts) ->
    cmd_create_sharded(Opts, libp2p_crypto:generate_keys(ed25519)).

cmd_create_sharded(Opts, Keys = #{ public := PubKey}) ->
    Password = proplists:get_value(password, Opts),
    Iterations = proplists:get_value(iterations, Opts, ?PBKDF2_DEFAULT_ITERATIONS),
    Shards = proplists:get_value(shards, Opts, ?SHARDED_DEFAULT_SHARDS),
    RecoveryThreshold = proplists:get_value(required_shards, Opts, ?SHARDED_DEFAULT_REQUIRED_SHARDS),
    Key = #sharded_key{
             version = ?SHARDED_KEY_V2,
             keymap = Keys,
             iterations = Iterations,
             key_shares = Shards,
             recovery_threshold = RecoveryThreshold
            },
    EncKeys = encrypt_key(Key, Password),
    Bins = [enc_key_to_bin(K) || K <- EncKeys],
    OutputFile0 = proplists:get_value(output_file, Opts),
    OutputFiles = [OutputFile0 ++ "." ++ integer_to_list(N) || N <- lists:seq(1, Shards)],
    Outputs = lists:zip(OutputFiles, Bins),
    lists:foreach(fun({OutFile, Bin}) ->
                          case write_output_file(OutFile, Bin, Opts) of
                              {error, file_exists} ->
                                  io:format("File ~p already exists~n", [OutFile]),
                                  halt(1);
                              ok ->
                                  io:format("Address: ~s~nFile: ~s~n",
                                            [libp2p_crypto:pubkey_to_b58(PubKey), OutFile])
                          end
                  end, Outputs).

write_output_file(OutFile, Bin, Opts) ->
    case {proplists:is_defined(force, Opts), file:read_file_info(OutFile)} of
        {false, {ok, _}} ->
            {error, file_exists};
        {_, _} ->
            file:write_file(OutFile, Bin),
            ok
    end.

%%
%% Info
%%

cmd_info(Opts) ->
    case load_keys(Opts) of
        {error, Filename, Error} ->
            io:format("Failed to read keys ~p: ~p~n", [Filename, Error]),
            halt(1);
        {ok, EncKeys} ->
            lists:foreach(fun({Filename, EncKey}) ->
                                  io:format("Address: ~s~nVersion: ~p~nFile: ~s~n",
                                            [libp2p_crypto:pubkey_to_b58(pubkey(EncKey)),
                                             key_version(EncKey),
                                             Filename])
                          end, EncKeys)
    end.

%%
%% Convert
%%

cmd_convert_config(Opts) ->
    cmd_verify_config(Opts).

cmd_convert_basic(Opts) ->
    cmd_convert_key(basic, Opts).

cmd_convert_sharded(Opts) ->
    cmd_convert_key(sharded, Opts).

cmd_convert_key(Target, Opts) ->
    case load_keys_and_decrypt(Opts) of
        {error, Filename, Error} ->
            io:format("Failed to read keys ~p: ~p~n", [Filename, Error]),
            halt(1);
        {error, {not_enough_shares, S, K}} ->
            io:format("not enough keyshares; have ~p, need ~b~n", [S, K]),
            halt(1);
        {error, mismatched_shares} ->
            io:format("Not all key shares are congruent with each other\n"),
            halt(1);
        {ok, Key} ->
            cmd_convert_key(Target, Opts, Key)
    end.

cmd_convert_key(basic, Opts, #basic_key{keymap=Keys}) ->
    cmd_create_basic(Opts, Keys);
cmd_convert_key(sharded, Opts, #basic_key{keymap=Keys}) ->
    cmd_create_sharded(Opts, Keys);
cmd_convert_key(basic, Opts, #sharded_key{keymap=Keys}) ->
    cmd_create_basic(Opts, Keys);
cmd_convert_key(sharded, Opts, #sharded_key{keymap=Keys}) ->
    cmd_create_sharded(Opts, Keys).



%%
%% verify
%%

cmd_verify_config(Opts) ->
    Password = string:strip(string:strip(io:get_line("Passsword: "), right, $\n), right, $\r),
    {ok, [{password, Password} | Opts]}.

cmd_verify(Opts) ->
    case load_keys_and_decrypt(Opts) of
        {error, Filename, Error} ->
            io:format("Failed to read keys ~p: ~p~n", [Filename, Error]),
            halt(1);
        {error, {not_enough_shares, S, K}} ->
            io:format("not enough keyshares; have ~p, need ~b~n", [S, K]),
            halt(1);
        {error, mismatched_shares} ->
            io:format("Not all key shares are congruent with each other\n"),
            halt(1);
        {error, Error} ->
            io:format("Verify: false (~p)~n", [Error]);
        {ok, _} ->
            io:format("Verify: true~n")
    end.

%%
%% balance
%%

cmd_balance(Opts) ->
    PB = fun(Key) ->
                 application:ensure_all_started(inets),
                 application:ensure_all_started(ssl),
                 URL = "https://explorer.helium.foundation/api/accounts/" ++ Key,
                 case httpc:request(URL) of
                     {error, Error} ->
                         io:format("Failed to get balance: ~p~n", [Error]),
                         halt(1);
                     {ok, {_Code, _Headers, Result}} ->
                         Data = proplists:get_value(<<"data">>, jsx:decode(list_to_binary(Result))),
                         io:format("Address: ~s~n",
                                   [binary_to_list(proplists:get_value(<<"address">>, Data))]),
                         io:format("Balance: ~p~n",
                                   [proplists:get_value(<<"balance">>, Data)]),
                         io:format("Data Credits: ~p~n",
                                   [proplists:get_value(<<"dc_balance">>, Data)]),
                         io:format("Security Balance: ~p~n",
                                   [proplists:get_value(<<"security_balance">>, Data)])
                 end
         end,
    case proplists:get_all_values(key, Opts) of
        [] ->
            case load_keys(Opts) of
                {error, Filename, Error} ->
                    io:format("Failed to read keys ~p: ~p~n", [Filename, Error]),
                    halt(1);
                {ok, Keys} ->
                    lists:foreach(fun({_, EncKey}) ->
                                          PB(libp2p_crypto:pubkey_to_b58(pubkey(EncKey)))
                                  end, Keys)
            end;
        [Keys] ->
            lists:foreach(fun({_, Key}) ->
                                  PB(libp2p_crypto:pubkey_to_b58(Key))
                          end, Keys)
    end.


%%
%% Utilities
%%


usage(Cmd, OptSpecs) ->
    getopt:usage(OptSpecs, io_lib:format("wallet ~s", [Cmd])).

handle_cmd(Specs, Cmd, Args, Fun) ->
    IdentOpts = fun(Opts) -> {ok, Opts} end,
    handle_cmd(Specs, Cmd, Args, IdentOpts, Fun).

handle_cmd(Specs, Cmd, Args, OptFun, Fun) ->
    case getopt:parse(Specs, Args) of
        {ok, {Opts,_}} ->
            case proplists:is_defined(help, Opts) of
                true -> usage(Cmd, Specs);
                false ->
                    {ok, NewOpts} = OptFun(Opts),
                    Fun(NewOpts)
            end;
        {error, _} ->
            usage(Cmd, Specs)
    end.


-spec encrypt_keymap(Key::binary(), IV::binary(), TagLength::pos_integer(), KeyMap::key_map())
                    -> {PubKeyBin::binary(), Encrypted::binary(), Tag::binary()}.
encrypt_keymap(Key, IV, TagLength, KeyMap=#{public := PubKey}) ->
    KeysBin = libp2p_crypto:keys_to_bin(KeyMap),
    PubKeyBin = libp2p_crypto:pubkey_to_bin(PubKey),
    {Encrypted, Tag} = crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, KeysBin, PubKeyBin, TagLength, true),
    {PubKeyBin, Encrypted, Tag}.

-spec decrypt_keymap(Key::binary(), IV::binary(), PubKeyBin::libp2p_crypto:pubkey_bin(),
                     Encryted::binary(), Tag::binary()) -> {ok, key_map()} | {error, term()}.
decrypt_keymap(Key, IV, PubKeyBin, Encrypted, Tag) ->
    case crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, Encrypted, PubKeyBin, Tag, false) of
        error ->
            {error, decrypt};
        Bin ->
            {ok, libp2p_crypto:keys_from_bin(Bin)}
    end.


key_version(#basic_key{version=Version}) ->
    {basic, Version};
key_version(#enc_basic_key{version=Version}) ->
    {basic, Version};
key_version(#enc_sharded_key{version=Version}) ->
    {sharded, Version};
key_version(#sharded_key{version=Version}) ->
    {sharded, Version}.

pubkey(#basic_key{ keymap=#{ public := PubKey}}) ->
    PubKey;
pubkey(#sharded_key{ keymap=#{ public := PubKey}}) ->
    PubKey;
pubkey(#enc_basic_key{ pubkey_bin=PubKeyBin}) ->
    libp2p_crypto:bin_to_pubkey(PubKeyBin);
pubkey(#enc_sharded_key{ pubkey_bin=PubKeyBin}) ->
    libp2p_crypto:bin_to_pubkey(PubKeyBin).

-spec encrypt_key(key(), Password::binary()) -> [enc_key()].
encrypt_key(#basic_key{ version=Version, keymap=KeyMap, iterations=Iterations}, Password) ->
    {IVLength, TagLength} = iv_and_tag_length(Version),
    IV = crypto:strong_rand_bytes(IVLength),
    Salt = crypto:strong_rand_bytes(8),
    {ok, AESKey} = pbkdf2:pbkdf2(sha256, Password, Salt, Iterations),
    {PubKeyBin, EncryptBin, Tag} = encrypt_keymap(AESKey, IV, TagLength, KeyMap),
    [#enc_basic_key{
        version=Version,
        pubkey_bin=PubKeyBin,
        iv = IV,
        salt = Salt,
        iterations = Iterations,
        tag = Tag,
        encrypted = EncryptBin
       }];
encrypt_key(#sharded_key{ version=Version, keymap=KeyMap, iterations=Iterations,
                          key_shares=Shares, recovery_threshold=RecoveryThreshold},
            Password) ->
    {IVLength, TagLength} = iv_and_tag_length(Version),
    %% sharding
    IV = crypto:strong_rand_bytes(IVLength),
    Salt = crypto:strong_rand_bytes(8),
    SSSKey = crypto:strong_rand_bytes(32),
    {ok, AESKey} = pbkdf2:pbkdf2(sha256, Password, Salt, Iterations),
    FinalKey = crypto:hmac(sha256, SSSKey, AESKey),
    KeyShares = erlang_sss:sss_create_keyshares(SSSKey, Shares, RecoveryThreshold),
    {PubKeyBin, EncryptBin, Tag} = encrypt_keymap(FinalKey, IV, TagLength, KeyMap),
    [#enc_sharded_key{
        version=Version,
        pubkey_bin=PubKeyBin,
        iterations=Iterations,
        iv = IV,
        salt = Salt,
        tag = Tag,
        key_shares=Shares,
        recovery_threshold = RecoveryThreshold,
        key_share = KS,
        encrypted = EncryptBin
      } || KS <- KeyShares].



iv_and_tag_length(?BASIC_KEY_V1) ->
    {8, 7};
iv_and_tag_length(?BASIC_KEY_V2) ->
    {12, 16};
iv_and_tag_length(?SHARDED_KEY_V1) ->
    {8, 7};
iv_and_tag_length(?SHARDED_KEY_V2) ->
    {12, 16}.


-spec enc_key_to_bin(enc_key()) -> binary().
enc_key_to_bin(#enc_basic_key{version=Version, pubkey_bin=PubKeyBin, iv=IV,
                              salt=Salt, iterations=Iterations, tag=Tag,
                              encrypted=Encrypted}) ->
    {IVLength, TagLength} = iv_and_tag_length(Version),
    <<Version:16/integer-unsigned-little,
      PubKeyBin:33/binary,
      IV:(IVLength)/binary,
      Salt:8/binary,
      Iterations:32/integer-unsigned-little,
      Tag:(TagLength)/binary,
      Encrypted/binary>>;
enc_key_to_bin(#enc_sharded_key{version=Version,pubkey_bin=PubKeyBin, iv=IV,
                                salt=Salt, iterations=Iterations, tag=Tag,
                                key_shares=Shares, recovery_threshold=RecoveryThreshold,
                                key_share=Share, encrypted=Encrypted}) ->
    {IVLength, TagLength} = iv_and_tag_length(Version),
    <<Version:16/integer-unsigned-little,
      Shares:8/integer-unsigned,
      RecoveryThreshold:8/integer-unsigned,
      Share:33/binary,
      PubKeyBin:33/binary,
      IV:(IVLength)/binary,
      Salt:8/binary,
      Iterations:32/integer-unsigned-little,
      Tag:(TagLength)/binary,
      Encrypted/binary>>.

-spec enc_key_from_bin(binary()) -> {ok, enc_key()} | {error, term()}.
enc_key_from_bin(<<Version:16/integer-unsigned-little, Payload/binary>>)
  when Version == ?BASIC_KEY_V1 orelse Version == ?BASIC_KEY_V2 ->
    {IVLength, TagLength} = iv_and_tag_length(Version),
    <<PubKeyBin:33/binary,
      IV:(IVLength)/binary,
      Salt:8/binary,
      Iterations:32/integer-unsigned-little,
      Tag:(TagLength)/binary,
      Encrypted/binary>> = Payload,
    {ok, #enc_basic_key {
            version=Version,
            pubkey_bin=PubKeyBin,
            iv = IV,
            salt = Salt,
            iterations = Iterations,
            tag = Tag,
            encrypted = Encrypted
           }};
enc_key_from_bin(<<Version:16/integer-unsigned-little, Payload/binary>>)
  when Version == ?SHARDED_KEY_V1 orelse Version == ?SHARDED_KEY_V2 ->
    {IVLength, TagLength} = iv_and_tag_length(Version),
    <<Shares:8/integer-unsigned,
      RecoveryThreshold:8/integer,
      Share:33/binary,
      PubKeyBin:33/binary,
      IV:(IVLength)/binary,
      Salt:8/binary,
      Iterations:32/integer-unsigned-little,
      Tag:(TagLength)/binary,
      Encrypted/binary>> = Payload,
    {ok, #enc_sharded_key{
            version=Version,
            pubkey_bin=PubKeyBin,
            iterations=Iterations,
            iv = IV,
            salt = Salt,
            tag = Tag,
            key_shares=Shares,
            recovery_threshold = RecoveryThreshold,
            key_share = Share,
            encrypted = Encrypted
           }};
enc_key_from_bin(_) ->
    {error, invalid_binary}.


-spec decrypt_keys([enc_key()], Password::binary()) -> {ok, key()} | {error, term()}.
decrypt_keys([#enc_basic_key{version=Version, salt=Salt, iterations=Iterations,
                             iv=IV, tag=Tag, pubkey_bin=PubKeyBin,
                             encrypted=Encrypted}], Password) ->
    {ok, AESKey} = pbkdf2:pbkdf2(sha256, Password, Salt, Iterations),
    case decrypt_keymap(AESKey, IV, PubKeyBin, Encrypted, Tag) of
        {error, Error} ->
            {error, Error};
        {ok, KeyMap} ->
            {ok, #basic_key {
                    version = Version,
                    keymap = KeyMap,
                    iterations = Iterations
                   }
            }
    end;
decrypt_keys([HeadShare = #enc_sharded_key{version=Version,
                                           recovery_threshold = K,
                                           iterations = Iterations,
                                           key_shares = Shards,
                                           salt = Salt,
                                           tag = Tag,
                                           iv = IV,
                                           pubkey_bin = PubKeyBin,
                                           encrypted = Encrypted}|_] = Shares, Password) ->
    case lists:all(fun(Share=#enc_sharded_key{}) ->
                           HeadShare#enc_sharded_key{key_share = <<>>} ==
                               Share#enc_sharded_key{key_share = <<>>};
                      (_) ->
                           false
                   end, Shares) of
        true when length(Shares) >= K ->
            KeyShares = lists:map(fun(#enc_sharded_key{key_share=Share}) -> Share end, Shares),
            SSSKey = erlang_sss:sss_combine_keyshares(KeyShares, K),
            {ok, AESKey} = pbkdf2:pbkdf2(sha256, Password, Salt, Iterations),
            FinalKey = crypto:hmac(sha256, SSSKey, AESKey),
            case decrypt_keymap(FinalKey, IV, PubKeyBin, Encrypted, Tag) of
                {error, Error} ->
                    {error, Error};
                {ok, KeyMap} ->
                    {ok, #sharded_key{
                            version = Version,
                            keymap = KeyMap,
                            iterations=Iterations,
                            key_shares = Shards,
                            recovery_threshold = K
                           }
                    }
            end;
        true ->
            {error, {not_enough_shares, length(Shares), K}};
        false ->
            {error, mismatched_shares}
    end.


-spec load_keys(Opts::list())
               -> {ok, [{Filename::string(), enc_key()}]} | {error, Filename::string(), term()}.
load_keys(Opts) ->
    Filenames = proplists:get_all_values(file, Opts),
    lists:foldl(fun(_, {error, _, _}=Acc) ->
                        Acc;
                   (Filename, {ok, Acc}) ->
                        case file:read_file(Filename) of
                            {error, Error} ->
                                {error, Filename, Error};
                            {ok, FileBin} ->
                                case enc_key_from_bin(FileBin) of
                                    {ok, EncKey} ->
                                        {ok, [{Filename, EncKey} | Acc]};
                                    {error, Error} -> {error, Filename, Error}
                                end
                        end
                end, {ok, []}, Filenames).

load_keys_and_decrypt(Opts) ->
    Password = proplists:get_value(password, Opts),
    case load_keys(Opts) of
        {error, Filename, Error} ->
            {error, Filename, Error};
        {ok, Keys} ->
            {_, EncKeys} = lists:unzip(Keys),
            decrypt_keys(EncKeys, Password)
    end.
