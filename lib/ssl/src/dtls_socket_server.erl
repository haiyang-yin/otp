-module(dtls_socket_server).
-behaviour(gen_server).

-include("dtls_transport.hrl").
-include("ssl_api.hrl").
-include("ssl_internal.hrl").

%%------------------------------------------------------------------------------
%% APIs
%%------------------------------------------------------------------------------
-export([start_link/0, stop/1]).
-export([open/6, listen/4, accept/1, setopts/2, controlling_process/1]).
-export([controlling_process/4, close/4, send/4]).

%%------------------------------------------------------------------------------
%% gen_server callbacks
%%------------------------------------------------------------------------------
-export([init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

%%------------------------------------------------------------------------------
%% local data structures
%%------------------------------------------------------------------------------
-record(state, {listen_sock     :: port(), % gen_udp listen socket
                new_clients     :: list(), % list of new client ports
                blocking          = false, % blocking for udp packets in client mode
                client_port_tbl            % table id of client port mapping table
               }).

-record(udp_client_port, {
                          status        :: inactive | active, % indicates the client port is active/inactive
                          data_receiver :: pid()              % callback for data packet
                         }).

-define(EMPTY, []).

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------
%%------------------------------------------------------------------------------
-spec start_link() -> {ok, pid()}  | {error, reason()}.

%%
%% Description: Starts a gen_server for listening on gen_udp socket.  
%%------------------------------------------------------------------------------
start_link() ->
    gen_server:start_link(?MODULE, [], []).

%%------------------------------------------------------------------------------
-spec stop(reference()) -> ok.

%%
%% Description: Stops a gen_server.  
%%------------------------------------------------------------------------------
stop(Ref) ->
    gen_server:cast(Ref, shutdown).

%%------------------------------------------------------------------------------
-spec open(reference(), inet:ip_address(), inet:ip_address(), inet:port_number(), listen_option(), timeout()) -> term().

%%
%% Description: Starts to open a udp socket.
%%------------------------------------------------------------------------------
open(Ref, Addr, ClientAddr, ClientPort, Opts, Timeout) ->
    gen_server:call(Ref, {open, [Addr, ClientAddr, ClientPort, Opts]}, Timeout).

%%------------------------------------------------------------------------------
-spec listen(reference(), inet:ip_address(), inet:port_number(), listen_option()) -> term().

%%
%% Description: Starts to listen on a transport address (ip + port).
%%------------------------------------------------------------------------------
listen(Ref, Addr, Port, Opts) ->
    gen_server:call(Ref, {listen, [Addr, Port, Opts]}).

%%------------------------------------------------------------------------------
-spec accept(reference()) -> term().

%%
%% Description: Checks if there is new client connection request. 
%%------------------------------------------------------------------------------
accept(Ref) ->
    gen_server:call(Ref, {accept}).

%%------------------------------------------------------------------------------
-spec setopts(reference(), listen_option()) -> term() | {error, no_new_client}.

%%
%% Description: Checks if there is new client connection request. 
%%------------------------------------------------------------------------------
setopts(Ref, Opts) ->
    gen_server:call(Ref, {setopts, [Opts]}).

%%------------------------------------------------------------------------------
-spec controlling_process(reference()) -> term() | {error, reason()}.

%%
%% Description: Transfer control of dtls server socket to specified process. 
%%------------------------------------------------------------------------------
controlling_process(Ref) ->
    gen_server:call(Ref, {controlling_process}).
 
%%------------------------------------------------------------------------------
-spec controlling_process(reference(), inet:ip_address(), inet:port_number(), pid()) -> term() | {error, reason()}.

%%
%% Description: Transfers control of dtls client socket to specified process. 
%%------------------------------------------------------------------------------
controlling_process(Ref, Addr, Port, Pid) ->
    gen_server:call(Ref, {controlling_process, [Addr, Port, Pid]}).
 
%%------------------------------------------------------------------------------
-spec close(reference(), inet:ip_address(), inet:port_number(), server | client) -> term() | {error, reason()}.

%%
%% Description: Closes dtls socket based on it transport address (ip + port). 
%%------------------------------------------------------------------------------
close(Ref, Addr, Port, Role) ->
    gen_server:call(Ref, {close, [Addr, Port, Role]}).

%%------------------------------------------------------------------------------
-spec send(reference(), inet:ip_address(), inet:port_number(), binary) -> ok | {error, reason()}.

%%
%% Description: Sends binary data to gen_udp socket. 
%%------------------------------------------------------------------------------
send(Ref, ClientAddr, ClientPort, Packet) ->
    gen_server:call(Ref, {send, [ClientAddr, ClientPort, Packet]}).

%%------------------------------------------------------------------------------
%% Callback functions
%%------------------------------------------------------------------------------
init(_Args) ->
    process_flag(trap_exit, true),
    {ok, #state{new_clients=[]}}.

handle_call({send, [ClientAddr, ClientPort, Packet]}, _From,
            #state{listen_sock=ListenSock} = State) ->
    Reply =
            try
                gen_udp:send(ListenSock, ClientAddr, ClientPort, Packet)
            catch
                _:Reason ->
                    {error, Reason}
            end,
   {reply, Reply, State};
handle_call({open, [Addr, ClientAddr, ClientPort, _Opts]}, _From, State) ->
    try
        %% pass 0, os system will allocate a dynamic port for use
        %% TODO: need to change ssl module to pass udp options to connect function as
        %% currently only gen_tcp options are passed here.
        %% case gen_udp:open(0, Opts) of
        case gen_udp:open(0, [{reuseaddr, true}, {header, 0}, {active, false}, {mode, binary}]) of
            {ok, Socket} ->
                inet:setopts(Socket, [binary, {active, false}]),
                {ok, LocalPort} = inet:port(Socket),
                TblName = convert_to_key(Addr, LocalPort),
                CliPortTbl = ets:new(list_to_atom(TblName),
                                     [set, {read_concurrency, true}, {write_concurrency, true}]),
                CKey = convert_to_key(ClientAddr, ClientPort),
                NewCliPort = #udp_client_port{status = inactive},
                true = ets:insert(CliPortTbl, {CKey, NewCliPort}),
                {reply, {ok, LocalPort}, State#state{listen_sock=Socket, blocking = true,
                                                     client_port_tbl = CliPortTbl}}; 
            {error, Reason1} ->
                {reply, {error, Reason1}, State}
        end
    catch
        _:Reason ->
            {reply, {error, Reason}, State}
    end; 
handle_call({listen, [Addr, Port, Opts]}, _From, State) ->
    try
        case gen_udp:open(Port, Opts) of
            {ok, Socket} ->
                inet:setopts(Socket, [binary, {active, true}]),
                Key = convert_to_key(Addr, Port),
                {reply, ok, State#state{listen_sock=Socket,
                     client_port_tbl = ets:new(list_to_atom(Key),
                                               [set,
                                                {read_concurrency, true},
                                                {write_concurrency, true}])}}; 
            {error, Reason1} ->
                {reply, {error, Reason1}, State}
        end
    catch
        _:Reason ->
            {reply, {error, Reason}, State}
    end; 
handle_call({accept}, _From, #state{new_clients=NewClients}=State) ->
    case NewClients of
        ?EMPTY ->
            {reply, {error, no_new_client}, State};
        [H|T] ->
            {reply, {ok, H}, State#state{new_clients=T}}
    end; 
handle_call({setopts, [_Opts]}, _From, State) ->
    % ssl module passes the tcp socket options which are not applicable for udp socket.
    % Reply = inet:setopts(ListenSock, Opts),
    {reply, ok, State}; 
handle_call({controlling_process}, _From, #state{listen_sock=ListenSock}=State) ->
    Reply = inet:setopts(ListenSock, [{active, once}]),
    {reply, Reply, State};
handle_call({controlling_process, [Addr, Port, Pid]}, _From,
            #state{client_port_tbl=CliPortTbl}=State) ->
    CKey = convert_to_key(Addr, Port),
    Reply =
            try ets:lookup(CliPortTbl, CKey) of
                ?EMPTY ->
                    {error, no_client_port};
                [{_, First} | _T] ->
                    true = ets:update_element(CliPortTbl, CKey,
                               {2, First#udp_client_port{status=active, data_receiver=Pid}}),
                    ok
            catch
                _:Reason ->
                    {error, Reason}
            end,
    {reply, Reply, State};
handle_call({close, [Addr, Port, Role]}, _From,
             #state{listen_sock=ListenSock, client_port_tbl=CliPortTbl}=State) ->
    case Role of 
        R when R =:= server; R =:= client ->
            gen_udp:close(ListenSock),
            ets:delete_all_objects(CliPortTbl);
        s_client ->
            CKey = convert_to_key(Addr, Port),
            ets:delete(CliPortTbl, CKey)
    end,
    Reply = ok,
    {reply, Reply, State#state{new_clients=[]}};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(shutdown, State) ->
    {stop, normal, State};
handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({udp, _Sock, Host, Port, Packet},
            #state{listen_sock=ListenSock,   % match udp listen socket
                   new_clients=Clients,      % match new client ports queue
                   blocking=IsBlockOn,       % flag to reject packets in client mode
                   client_port_tbl=CliPortTbl}=State) ->
    CKey = convert_to_key(Host, Port),
    % must be one as we only allow one entry 
    NewState =
            try ets:lookup(CliPortTbl, CKey) of
                ?EMPTY ->
                    if
                        IsBlockOn =:= false ->
                            NewClientPort = #udp_client_port{status = inactive},
                            true = ets:insert(CliPortTbl, {CKey, NewClientPort}),
                            State#state{new_clients=lists:append(
                                            Clients, [{Host, Port}])};
                        true ->
                            %% when blocking is true, all packets from other hosts
                            %% will be ignored.
                            State
                    end;
                [{_, #udp_client_port{status=S, data_receiver=R}} | _T] ->
                    if
                        S =:= active ->
                            % controlling_process was issued on this client port
                            R! {udp, #dtls_socket{}, Packet};  
                        true ->
                            % controlling_process was not issued on this client port
                            void
                    end,
                    State
            catch 
                _:_ ->
                    State
            end,
    ok = inet:setopts(ListenSock, [{active, once}]),
    {noreply, NewState};
handle_info({udp_closed, _Sock}, State) ->
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_, #state{listen_sock=ListenSock, client_port_tbl=CliPortTbl}) ->
    case ets:info(CliPortTbl) of
        undefined ->
            void;
        _ ->
            ets:delete(CliPortTbl),
            % make sure the udp socket closed anyway
            gen_udp:close(ListenSock)
    end,
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%------------------------------------------------------------------------------
%% Internal Functions
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

