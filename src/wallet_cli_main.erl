-module(wallet_cli_main).

-export([main/1]).

main(["create" | Args]) ->
    AppDir = filename:dirname(filename:dirname(code:where_is_file("wallet"))),
    os:putenv("NIF_PATH", AppDir),

    OptSpecs =
        [
         {output_file, $o, "output",  {string, "wallet.key"}, "Output file to store the key in"},
         {force,       $f, "force",   undefined,               "Overwrite an existing file"},
         {iterations,  $i, "iterations", {integer, 100000},    "Number of PBKDF2 iterations"},
         {shards,      $n, "shards",  {integer, 1},            "Number of shards to break the key into"},
         {required_shards, $k, "required-shards",  integer,     "Number of shards required to recover the key"},
         {help,        $h, "help",    undefined,               "Print this help text"}
        ],

    handle_cmd(OptSpecs, Args, fun cmd_create_config/1, fun cmd_create/1);
main(["info" | Args]) ->
    OptSpecs =
        [
         {file, undefined, undefined, {string, "wallet.key"}, "Wallet file to load"},
         {help, $h,        "help",    undefined,             "Print this help text"}
        ],
    handle_cmd(OptSpecs, Args, fun cmd_info/1);
main(["verify" | Args]) ->
    AppDir = filename:dirname(filename:dirname(code:where_is_file("wallet"))),
    os:putenv("NIF_PATH", AppDir),

    OptSpecs =
        [
         {file, $f, "file", {string, "wallet.key"}, "Wallet file to load"},
         {help, $h,        "help",    undefined,             "Print this help text"}
        ],
    handle_cmd(OptSpecs, Args, fun cmd_verify_config/1, fun cmd_verify/1);
main(["balance" | Args]) ->
    OptSpecs =
        [
         {key,  $k,        "key",     string,                "Public key to get balance for"},
         {file, undefined, undefined, {string, "wallet.key"}, "Wallet file to load"},
         {help, $h,        "help",    undefined,              "Print this help text"}
        ],
    handle_cmd(OptSpecs, Args, fun cmd_balance/1);
main(_) ->
    OptSpecs =
        [
         {create, undefined, undefined, undefined, "Create a new encrypted wallet"},
         {verify, undefined, undefined, undefined, "Verify an ecnrypted wallet"},
         {info,   undefined, undefined, undefined, "Get public wallet address"},
         {balance,undefined, undefined, undefined, "Get balance for a wallet or a given address"}
        ],
    usage(OptSpecs).

%%
%% create
%%

cmd_create_config(Opts) ->
    Password = string:strip(string:strip(io:get_line("Password: "), right, $\n), right, $\r),
    PasswordVerify = string:strip(string:strip(io:get_line("Verify Password: "), right, $\n), right, $\r),
    case Password == PasswordVerify of
        false ->
            io:format("Passwords do not match~n"),
            false;
        true ->
            {ok, [{password, Password} | Opts]}
    end.

cmd_create(Opts) ->
    Keys = #{ public := PubKey } = libp2p_crypto:generate_keys(ed25519),
    Password = proplists:get_value(password, Opts),
    Iterations = proplists:get_value(iterations, Opts),
    Shards = proplists:get_value(shards, Opts),
    RecoveryThreshold = proplists:get_value(required_shards, Opts),
    case Shards > 1 andalso is_integer(RecoveryThreshold) andalso RecoveryThreshold > 1 andalso Shards > RecoveryThreshold of
        true  ->
            ok;
        false when Shards == 1 ->
            ok;
        false ->
            io:format("If shards (~b) > 1 then recovery_shards (~p) must be specified and recovery_shards must be less than shards\n", [Shards, RecoveryThreshold]),
            halt(1)
    end,
    Bins = encrypt_keys(Keys, Password, Iterations, Shards, RecoveryThreshold),
    OutputFile0 = proplists:get_value(output_file, Opts),
    OutputFiles = case length(Bins) of
                      1 ->
                          [OutputFile0];
                      _ ->
                          [ OutputFile0 ++ "." ++ integer_to_list(N) || N <- lists:seq(1, Shards)]
                  end,
    Outputs = lists:zip(OutputFiles, Bins),
    lists:foreach(fun({OutputFile, Bin}) ->
                          case {proplists:is_defined(force, Opts), file:read_file_info(OutputFile)} of
                              {false, {ok, _}} ->
                                  io:format("File ~p already exists~n", [OutputFile]);
                              {_, _} ->
                                  file:write_file(OutputFile, Bin),
                                  io:format("Address: ~s~nFile: ~s~n",
                                            [libp2p_crypto:pubkey_to_b58(PubKey), OutputFile])
                          end
                  end, Outputs).

%%
%% Info
%%

cmd_info(Opts) ->
    case load_keys(Opts) of
        {error, Filename, Error} ->
            io:format("Failed to read keys ~p: ~p~n", [Filename, Error]);
        {ok, #{ pubkey := PubKey, filename := Filename }} ->
            io:format("Address: ~s~nFile: ~s~n",
                      [libp2p_crypto:pubkey_to_b58(PubKey), Filename])
    end.

%%
%% verify
%%

cmd_verify_config(Opts) ->
    Password = string:strip(string:strip(io:get_line("Passsword: "), right, $\n), right, $\r),
    {ok, [{password, Password} | Opts]}.

cmd_verify(Opts) ->
    Password = proplists:get_value(password, Opts),
    case load_keys(Opts) of
        {error, Filename, Error} ->
            io:format("Failed to read keys ~p: ~p~n", [Filename, Error]);
        {ok, KeyMap} ->
            Decrypt = case decrypt_keys(KeyMap, Password) of
                          error -> false;
                          _ -> true
                      end,
            io:format("Verify: ~p~n", [Decrypt])
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
                         io:format("Failed to get balance: ~p~n", [Error]);
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
    case proplists:get_value(key, Opts, false) of
        false ->
            case load_keys(Opts) of
                {error, Filename, Error} ->
                    io:format("Failed to read keys ~p: ~p~n", [Filename, Error]);
                {ok, #{ pubkey := PubKey}} ->
                    PB(libp2p_crypto:pubkey_to_b58(PubKey))
            end;
        KeyStr ->
            PB(KeyStr)
    end.


%%
%% Utilities
%%


usage(OptSpecs) ->
    getopt:usage(OptSpecs, "wallet").

handle_cmd(Specs, Args, Fun) ->
    IdentOpts = fun(Opts) -> {ok, Opts} end,
    handle_cmd(Specs, Args, IdentOpts, Fun).

handle_cmd(Specs, Args, OptFun, Fun) ->
    case getopt:parse(Specs, Args) of
        {ok, {Opts,_}} ->
            case proplists:is_defined(help, Opts) of
                true -> usage(Specs);
                false ->
                    case OptFun(Opts) of
                        false -> false;
                        {ok, NewOpts} -> Fun(NewOpts)
                    end
            end;
        {error, _} ->
            usage(Specs)
    end.

encrypt_keys(Keys=#{public := PubKey}, Password, Iterations, 1, _) ->
    %% No sharding
    IV = crypto:strong_rand_bytes(8),
    Salt = crypto:strong_rand_bytes(8),
    KeysBin = libp2p_crypto:keys_to_bin(Keys),
    PubKeyBin = libp2p_crypto:pubkey_to_bin(PubKey),
    Shares = 1,
    RecoveryThreshold = 1,
    {ok, AESKey} = pbkdf2:pbkdf2(sha256, Password, Salt, Iterations),
    {EncryptBin, Tag} = crypto:crypto_one_time_aead(aes_256_gcm,
                                                    AESKey,
                                                    IV,
                                                    KeysBin,
                                                    PubKeyBin,
                                                    7,
                                                    true),
    [<<Shares:8/integer-unsigned, RecoveryThreshold:8/integer, PubKeyBin/binary, IV/binary, Salt/binary, Iterations:32/integer-unsigned-little, Tag/binary, EncryptBin/binary>>];
encrypt_keys(Keys=#{public := PubKey}, Password, Iterations, Shares, RecoveryThreshold) ->
    %% sharding
    IV = crypto:strong_rand_bytes(8),
    Salt = crypto:strong_rand_bytes(8),
    SSSKey = crypto:strong_rand_bytes(32),
    KeysBin = libp2p_crypto:keys_to_bin(Keys),
    PubKeyBin = libp2p_crypto:pubkey_to_bin(PubKey),
    {ok, AESKey} = pbkdf2:pbkdf2(sha256, Password, Salt, Iterations),
    FinalKey = crypto:hmac(sha256, SSSKey, AESKey),
    KeyShares = erlang_sss:sss_create_keyshares(SSSKey, Shares, RecoveryThreshold),
    {EncryptBin, Tag} = crypto:crypto_one_time_aead(aes_256_gcm,
                                                    FinalKey,
                                                    IV,
                                                    KeysBin,
                                                    PubKeyBin,
                                                    7,
                                                    true),
    [ <<Shares:8/integer-unsigned, RecoveryThreshold:8/integer, KS:33/binary, PubKeyBin/binary, IV/binary, Salt/binary, Iterations:32/integer-unsigned-little, Tag/binary, EncryptBin/binary>> || KS <- KeyShares ].


decrypt_keys([#{ shares := 1, pubkey_bin := PubKeyBin, iv := IV, salt := Salt, iterations := Iterations, tag := Tag, cipher_text := Encrypted}], Password) ->
    %% no shares
    {ok, AESKey} = pbkdf2:pbkdf2(sha256, Password, Salt, Iterations),
    crypto:crypto_one_time_aead(aes_256_gcm,
                                AESKey,
                                IV,
                                Encrypted,
                                PubKeyBin,
                                Tag,
                                false);
decrypt_keys([HeadShare = #{recovery_threshold := K, iterations := Iterations, salt := Salt, tag := Tag, iv := IV, pubkey_bin := PubKeyBin, cipher_text := Encrypted}|_] = Shares, Password) ->
    case lists:all(fun(Share) ->
                           maps:without([filename, share], HeadShare) == maps:without([filename, share], Share)
                   end, Shares) of
        true when length(Shares) >= K ->
            KeyShares = lists:map(fun(#{share := Share}) -> Share end, Shares),
            SSSKey = erlang_sss:sss_combine_keyshares(KeyShares, K), 
            {ok, AESKey} = pbkdf2:pbkdf2(sha256, Password, Salt, Iterations),
            FinalKey = crypto:hmac(sha256, SSSKey, AESKey),
            crypto:crypto_one_time_aead(aes_256_gcm,
                                        FinalKey,
                                        IV,
                                        Encrypted,
                                        PubKeyBin,
                                        Tag,
                                        false);
        true ->
            io:format("not enough keyshares; have ~p, need ~b\n", [length(Shares), K]),
            halt(1);
        false ->
            io:format("Not all key shares are congruent with each other\n"),
            halt(1)
    end.


load_keys(Opts) ->
    Filenames = proplists:get_all_values(file, Opts),
    lists:foldl(fun(_, {error, _, _}=Acc) ->
                        Acc;
                   (Filename, {ok, Acc}) ->
                        case file:read_file(Filename) of
                            {error, Error} ->
                                {error, Filename, Error};
                            {ok, <<1:8/integer-unsigned, 1:8/integer-unsigned, PubKeyBin:33/binary, IV:8/binary, Salt:8/binary, Iterations:32/integer-unsigned-little, Tag:7/binary, Encrypted/binary>>} ->
                                {ok, [#{ filename => Filename,
                                        pubkey_bin => PubKeyBin,
                                        pubkey => libp2p_crypto:bin_to_pubkey(PubKeyBin),
                                        salt => Salt,
                                        iterations => Iterations,
                                        iv => IV,
                                        tag => Tag,
                                        cipher_text => Encrypted,
                                        shares => 1
                                      } | Acc]};
                            {ok, <<N:8/integer-unsigned, K:8/integer-unsigned, Share:33/binary, PubKeyBin:33/binary, IV:8/binary, Salt:8/binary, Iterations:32/integer-unsigned-little, Tag:7/binary, Encrypted/binary>>} ->
                                {ok, [ #{ filename => Filename,
                                        pubkey_bin => PubKeyBin,
                                        pubkey => libp2p_crypto:bin_to_pubkey(PubKeyBin),
                                        salt => Salt,
                                        iterations => Iterations,
                                        iv => IV,
                                        tag => Tag,
                                        cipher_text => Encrypted,
                                        shares => N,
                                        recovery_threshold => K,
                                        share => Share
                                      } | Acc]}

                        end
                end, {ok, []}, Filenames).
