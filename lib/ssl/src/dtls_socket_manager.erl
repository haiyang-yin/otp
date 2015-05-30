%%-------------------------------------------------------------------------------
%% dtls_socket_manager manages an ETS table which does mapping between
%% transport address (ip + port) and dtls_server_socket process id. Each
%% dtls_socket_server is a gen_server running on listening to one gen_udp
%% socket.
%%-------------------------------------------------------------------------------
-module(dtls_socket_manager).

%%-------------------------------------------------------------------------------
%% Public APIs
%%-------------------------------------------------------------------------------
-export([init/0, deinit/0]).
-export([new_server_port/3, check_server_port/2, delete_server_port/2]).
-export([get_server_pid/2]).

-include("ssl_internal.hrl").

-record(udp_server_port, { socket_server_pid :: pid() }).

-define(EMPTY, []).
-define(UDP_SERVER_PORT_TBL_NAME, udp_server_port_tbl).
 
%%------------------------------------------------------------------------------
%% API Functions
%%------------------------------------------------------------------------------
%%------------------------------------------------------------------------------
-spec init() -> ok  | {error, reason()}.

%%
%% Description: Creates an ETS table to store mapping between transport
%% address and server process id. If the table already exists, just clear the
%% table. It should be called when ssl module is started, ideally in
%% ssl:start() function. 
%%------------------------------------------------------------------------------
init() ->
    case ets:info(?UDP_SERVER_PORT_TBL_NAME) of
        undefined ->
            % create a new table for managing server ports
            ets:new(?UDP_SERVER_PORT_TBL_NAME,
                    [set,                      % one key, one object, no order
                     public,                   % allow access from different process
                     named_table,              % access this table by its name
                     {read_concurrency, true}, % optimized for concurrent read 
                     {write_concurrency, true} % optimized for concurrent write
                    ]);
        _ ->
            % clear the table if it exists
            ets:delete_all_objects(?UDP_SERVER_PORT_TBL_NAME)
    end,
    ok.

%%------------------------------------------------------------------------------
-spec deinit() -> ok  | {error, no_udp_server_port_tbl}.

%%
%% Description: If table exists, stops all dtls_socket_server processes and
%% deletes the ETS table as well.
%%------------------------------------------------------------------------------
deinit() ->
    case ets:info(?UDP_SERVER_PORT_TBL_NAME) of
        undefined ->
            {error, no_udp_server_port_tbl};
        _ ->
            ets:foldl(fun({_, #udp_server_port{socket_server_pid=P}}, _) ->
                          dtls_socket_server:stop(P)
                      end,
                      notused,
                      ?UDP_SERVER_PORT_TBL_NAME),
            ets:delete(?UDP_SERVER_PORT_TBL_NAME),
            ok
    end.
 
%%------------------------------------------------------------------------------
-spec new_server_port(inet:ip_address(), inet:port_number(), pid()) -> ok  | {error, reason()}.

%%
%% Description: Adds new mapping entry into table. 
%%------------------------------------------------------------------------------
new_server_port(Addr, Port, Pid) ->
    Key = convert_to_key(Addr, Port),
    try ets:lookup(?UDP_SERVER_PORT_TBL_NAME, Key) of
        ?EMPTY ->
            NewPort = #udp_server_port{ socket_server_pid=Pid },
            % server port was not present, go ahead and creat a new one
            true = ets:insert(?UDP_SERVER_PORT_TBL_NAME, {Key, NewPort}),
            ok;
        _ ->
            ok 
    catch
        _:Reason ->
            {error, Reason} 
    end.

%%------------------------------------------------------------------------------
-spec check_server_port(inet:ip_address(), inet:port_number()) -> true  | false.

%%
%% Description: Checks whether the mapping entry exists for a transport address.
%% true if the entry exists, false otherwise. 
%%------------------------------------------------------------------------------
check_server_port(Addr, Port) ->
    Key = convert_to_key(Addr, Port),
    try ets:lookup(?UDP_SERVER_PORT_TBL_NAME, Key) of
        ?EMPTY ->
            false;
        _ ->
            true
    catch
        _:_ ->
            false
    end.

%%------------------------------------------------------------------------------
-spec get_server_pid(inet:ip_address(), inet:port_number()) -> true  | false.

%%
%% Description: Gets dtls_socket_server process id by transport address (ip + port). 
%%------------------------------------------------------------------------------
get_server_pid(Addr, Port) ->
    Key = convert_to_key(Addr, Port),
    try ets:lookup(?UDP_SERVER_PORT_TBL_NAME, Key) of
        ?EMPTY ->
            {error, badarg};
        [{_, #udp_server_port{socket_server_pid=P}} | _T ] ->
            {ok, P} 
    catch
        _:Reason ->
            {error, Reason} 
    end.

%%------------------------------------------------------------------------------
-spec delete_server_port(inet:ip_address(), inet:port_number()) -> ok  | {error, reason()}.

%%
%% Description: Deletes a mapping entry by transport address (ip + port). 
%%------------------------------------------------------------------------------
delete_server_port(Addr, Port) ->
    Key = convert_to_key(Addr, Port),
    try ets:lookup(?UDP_SERVER_PORT_TBL_NAME, Key) of
        ?EMPTY ->
            {error, entry_not_found};
        _ ->
            true = ets:delete(?UDP_SERVER_PORT_TBL_NAME, Key), 
            ok 
    catch
        _:Reason ->
            {error, Reason} 
    end.

%%------------------------------------------------------------------------------
%% Internal Functions
%%------------------------------------------------------------------------------
%%------------------------------------------------------------------------------
%% Description: Utility function to convert transport address (ip + adress) to
%% string format in order to form the key for ets table. 
%%------------------------------------------------------------------------------
convert_to_key(localhost, Port) when is_integer(Port) ->
    string:join(["localhost", integer_to_list(Port)], ":");
convert_to_key(Addr, Port) when is_integer(Port) ->
    case inet:ntoa(Addr) of
        {error, Reason} ->
           {error, Reason};
        AddrStr ->
           string:join([AddrStr, integer_to_list(Port)], ":")
    end.
