-module(wallet_cli_main).

-export([main/1]).

main(["create" | Args]) ->
    AppDir = filename:dirname(filename:dirname(code:where_is_file("wallet"))),
    os:putenv("NIF_PATH", AppDir),

    OptSpecs =
        [
         {output_file, $o, "output",  {string, "wallet.key"}, "Output file to store the key in"},
         {force,       $f, "force",   undefined,               "Overwrite an existing file"},
         {help,        $h, "help",    undefined,               "Print this help text"}
        ],

    handle_cmd(OptSpecs, Args, fun cmd_create_config/1, fun cmd_create/1);
main(["info" | Args]) ->
    OptSpecs =
        [
         {file, undefined, undefined, {string, "wallet.key", "Wallet file to load"}},
         {help, $h,        "help",    undefined,             "Print this help text"}
        ],
    handle_cmd(OptSpecs, Args, fun cmd_info/1);
main(["verify" | Args]) ->
    OptSpecs =
        [
         {file, undefined, undefined, {string, "wallet.key", "Wallet file to load"}},
         {help, $h,        "help",    undefined,             "Print this help text"}
        ],
    handle_cmd(OptSpecs, Args, fun cmd_verify_config/1, fun cmd_verify/1);
main(["balance" | Args]) ->
    OptSpecs =
        [
         {key,  $k,        "key",     string,                "Public key to get balance for"},
         {file, undefined, undefined, {string, "wallet.key", "Wallet file to load"}},
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
    Password = io:get_line("Password: "),
    PasswordVerify = io:get_line("Verify Password: "),
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
    Bin = encrypt_keys(Keys, Password),
    OutputFile = proplists:get_value(output_file, Opts),
    case {proplists:is_defined(force, Opts), file:read_file_info(OutputFile)} of
        {false, {ok, _}} ->
            io:format("File ~p already exists~n", [OutputFile]);
        {_, _} ->
            file:write_file(OutputFile, Bin),
            io:format("Address: ~s~nFile: ~s~n",
                      [libp2p_crypto:pubkey_to_b58(PubKey), OutputFile])
    end.

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
    Password = io:get_line("Passsword: "),
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

encrypt_keys(Keys=#{public := PubKey}, Password) ->
    IV = crypto:strong_rand_bytes(8),
    KeysBin = libp2p_crypto:keys_to_bin(Keys),
    PubKeyBin = libp2p_crypto:pubkey_to_bin(PubKey),
    {EncryptBin, Tag} = crypto:crypto_one_time_aead(aes_256_gcm,
                                                    crypto:hash(sha256, Password),
                                                    IV,
                                                    KeysBin,
                                                    PubKeyBin,
                                                    7,
                                                    true),
    <<PubKeyBin/binary, IV/binary, Tag/binary, EncryptBin/binary>>.

decrypt_keys(#{ pubkey_bin := PubKeyBin, iv := IV, tag := Tag, cipher_text := Encrypted}, Password) ->
    crypto:crypto_one_time_aead(aes_256_gcm,
                                crypto:hash(sha256, Password),
                                IV,
                                Encrypted,
                                PubKeyBin,
                                Tag,
                                false).

load_keys(Opts) ->
    Filename = proplists:get_value(file, Opts, "wallet.key"),
    case file:read_file(Filename) of
        {error, Error} ->
            {error, Filename, Error};
        {ok, FileBin} ->
            <<PubKeyBin:33/binary, IV:8/binary, Tag:7/binary, Encrypted/binary>> = FileBin,
            {ok, #{ filename => Filename,
                    pubkey_bin => PubKeyBin,
                    pubkey => libp2p_crypto:bin_to_pubkey(PubKeyBin),
                    iv => IV,
                    tag => Tag,
                    cipher_text => Encrypted
                   }}
    end.
