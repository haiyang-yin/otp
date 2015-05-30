%%% Purpose : refactor udp transport to behaves like tcp mode for dtls
%%% data layer relaying. 

-module(dtls_transport).

%%------------------------------------------------------------------------------
%% API Prototypes
%%------------------------------------------------------------------------------
-export([open/4, connect/3, connect/4]).
-export([listen/1, listen/2, setopts/2, accept/1, accept/2, port/1]).
-export([controlling_process/2, peername/1, send/2, close/1]).

%%------------------------------------------------------------------------------
%% Includes 
%%------------------------------------------------------------------------------
-include("dtls_transport.hrl").
-include("ssl_api.hrl").
-include("ssl_internal.hrl").

%%------------------------------------------------------------------------------
%% Defintions 
%%------------------------------------------------------------------------------
-define(ACCEPT_CHECK_TIMER, 1000).

%%------------------------------------------------------------------------------
%% API Functions 
%%------------------------------------------------------------------------------
%%------------------------------------------------------------------------------
-spec open(inet:ip_address(), inet:port_number(), connect_option(), timeout())
      -> {ok, #dtls_socket{}} | {error, reason()}.

%%
%% Description: Creates a new dtls_socket. 
%%------------------------------------------------------------------------------
open(ClientAddr, ClientPort, Opts, Timeout) ->
    %% Checks whether caller specifies network interface to use for opening
    %% listen socket.
    case get_option(ip, Opts) of
        {error, option_not_found} ->
            % If no network interface specified, set it to default value - localhost.
            Addr = localhost;
        Val ->
            Addr = Val
    end,
    case dtls_socket_server:start_link() of
        {ok, Pid} ->
            case dtls_socket_server:open(Pid, Addr, ClientAddr, ClientPort, Opts, Timeout) of
                {ok, LocalPort} ->
                    ok = dtls_socket_manager:new_server_port(Addr, LocalPort, Pid),
                    {ok, #dtls_socket{role = client,
                                      local_addr=Addr, local_port=LocalPort,
                                      client_addr=ClientAddr, client_port=ClientPort}};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, _} ->
            {error, noproc} 
    end. 

%%------------------------------------------------------------------------------
-spec connect(inet:ip_address(), inet:port_number(), connect_option())
      -> {ok, #dtls_socket{}} | {error, reason()}.
-spec connect(inet:ip_address(), inet:port_number(), connect_option(), timeout())
      -> {ok, #dtls_socket{}} | {error, reason()}.

%%
%% Description: Connect to a UDP server.
%%------------------------------------------------------------------------------
connect(ClientAddr, ClientPort, Opts) ->
    connect(ClientAddr, ClientPort, Opts, infinity).

connect(ClientAddr, ClientPort, Opts, Timeout) ->
    open(ClientAddr, ClientPort, Opts, Timeout).

%%------------------------------------------------------------------------------
-spec listen(inet:port_number()) -> {ok, #dtls_socket{}}  | {error, reason()}.
-spec listen(inet:port_number(), [listen_option()]) -> {ok, #dtls_socket{}}  | {error, reason()}.

%%
%% Description: Creates an ssl listen socket. 
%%------------------------------------------------------------------------------
listen(Port) ->
    listen(Port, [binary, {reuseaddr, true}]).

listen(Port, Opts) ->
    %% Checks whether caller specifies network interface to use for opening
    %% listen socket.
    case get_option(ip, Opts) of
        {error, option_not_found} ->
            % If no network interface specified, set it to default value - localhost.
            Addr = localhost;
        Val ->
            Addr = Val
    end,
    case dtls_socket_server:start_link() of
        {ok, Pid} ->
            % server process was created successfully
            ok = dtls_socket_manager:new_server_port(Addr, Port, Pid),
            case dtls_socket_server:listen(Pid, Addr, Port, Opts) of
                ok ->
                    {ok, #dtls_socket{local_addr=Addr, local_port=Port, role=server}};
                {error, Reason} ->
                    dtls_socket_manager:delete_server_port(Addr, Port),
                    {error, Reason}
            end;
        Other -> Other
    end. 

%%------------------------------------------------------------------------------
-spec setopts(#dtls_socket{}, [listen_option()]) -> ok | {error, reason()}.

%%
%% Description: Sets socket options on the socket. Unlike tcp socket, we don't 
%% set socket options for client sockets as they use the same udp socket as
%% udp listen socket.
%%------------------------------------------------------------------------------
setopts(#dtls_socket{role=Role, local_addr=Addr, local_port=Port}, Opts) ->
    case Role of 
        R when R =:= server; R =:= client ->
            case dtls_socket_manager:get_server_pid(Addr, Port) of
                {ok, Pid} ->
                    dtls_socket_server:setopts(Pid, Opts);
                Other -> Other 
            end;
        s_client ->
            %% just do nothing
            ok;
        _ ->
            {error, badarg}
    end. 

%%------------------------------------------------------------------------------
-spec accept(#dtls_socket{}) -> {ok, #dtls_socket{}} | {error, no_new_client|reason()}.
-spec accept(#dtls_socket{}, integer()) -> {ok, #dtls_socket{}} | {error, no_new_client|reason()}.

%%
%% Description: This function is similar to gen_tcp:accept() function. It will
%% wait for client socket to connect, or stop when listen socket closed or
%% until network errors occur, or timer expires when given Timeout parameter
%% set by caller.
%%------------------------------------------------------------------------------
accept(ListenSocket) ->
    accept(ListenSocket, infinity).

accept(#dtls_socket{role=Role, local_addr=Addr, local_port=Port}=Socket, Timeout) -> 
    case Role of 
        server ->
            CurrentPid = self(),
            case dtls_socket_manager:get_server_pid(Addr, Port) of
                {ok, ServerPid} ->
                    case dtls_socket_server:accept(ServerPid) of
                        {ok, {ClientAddr, ClientPort}} ->
                            {ok, Socket#dtls_socket{role=client,
                                     client_addr=ClientAddr, client_port=ClientPort}};
                        {error, no_new_client} ->
                            if
                                Timeout =/= infinity ->
                                    T1 = erlang:start_timer(Timeout, self(),
                                                            timeout_for_accept),
                                    T2 = erlang:start_timer(?ACCEPT_CHECK_TIMER,
                                                            self(), timeout_for_check), 
                                    accept_timeout_loop(CurrentPid, ServerPid, Socket, T1, T2);
                                true ->
                                    T2 = erlang:start_timer(?ACCEPT_CHECK_TIMER, self(),
                                        timeout_for_check),
                                    accept_infinity_loop(CurrentPid, ServerPid, Socket, T2)
                            end
                    end;
                Other -> Other
            end;
        _ ->
            {error, badarg}
    end. 

%%------------------------------------------------------------------------------
-spec port(#dtls_socket{}) -> {ok, inet:port_number()} | {error, reason()}.

%%
%% Description: Utiltiy function to return the port number associated with the socket.
%%------------------------------------------------------------------------------
port(#dtls_socket{role=Role, local_port=Port, client_port=ClientPort}) ->
    case Role of 
        server ->
            {ok, Port};
        R when R =:= s_client; R =:= client ->
            {ok, ClientPort};
        _ ->
            {error, badarg}
    end.

%%------------------------------------------------------------------------------
-spec controlling_process(#dtls_socket{}, pid()) -> ok | {error, reason()}.

%%
%% Description: Changes the controlling process to the specific process. This
%% is used by dtls_connection fsm to control client socket in order to
%% receive raw data packets.  
%%------------------------------------------------------------------------------
controlling_process(#dtls_socket{role=Role, local_addr=Addr, local_port=Port,
                                 client_addr=ClientAddr, client_port=ClientPort},
                                 CtrlPid) ->
    case dtls_socket_manager:get_server_pid(Addr, Port) of
        {ok, Pid} ->
            case Role of 
                server ->
                    dtls_socket_server:controlling_process(Pid);
                client ->
                    dtls_socket_server:controlling_process(Pid),
                    dtls_socket_server:controlling_process(
                        Pid, ClientAddr, ClientPort, CtrlPid);
                s_client ->
                    dtls_socket_server:controlling_process(
                        Pid, ClientAddr, ClientPort, CtrlPid);
                _ -> {error, badarg}
            end; 
        {error, Reason} -> {error, Reason}
    end. 

%%------------------------------------------------------------------------------
-spec peername(#dtls_socket{}) -> {ok | {inet:ip_address(), inet:port_number()}}.

%%
%% Description: Utility function to return transport address (ip + port).
%%------------------------------------------------------------------------------
peername(#dtls_socket{role=Role, local_addr=Addr, local_port=Port,
                      client_addr=ClientAddr, client_port=ClientPort}) ->
    case Role of 
        server ->
            {ok, {Addr, Port}};
        R when R =:= s_client; R =:= client ->
            {ok, {ClientAddr, ClientPort}};
        _ -> {error, badarg}
    end.

%%------------------------------------------------------------------------------
-spec send(#dtls_socket{}, binary()) -> ok | {error, reason()}.

%%
%% Description: Sends binary data to network, which is determined by socket.
%% Similar to gen_tcp handling, it is not allowed to send data to udp
%% listen socket (even you can). 
%%------------------------------------------------------------------------------
send(#dtls_socket{role=Role, local_addr=Addr, local_port=Port,
                  client_addr=ClientAddr, client_port=ClientPort},
                  Packet) ->
    case dtls_socket_manager:get_server_pid(Addr, Port) of
        {ok, Pid} ->
            case Role of 
                R when R =:= s_client; R =:= client ->
                    internal_send(Pid, ClientAddr, ClientPort, Packet);
                _ -> {error, badarg}
            end; 
        {error, Reason} ->
            {error, Reason}
    end.
    
%%------------------------------------------------------------------------------
-spec close(#dtls_socket{}) -> ok.

%%
%% Description: Closes the socket. When listen socket is closed, all client
%% sockets will be 'logically' closed because those client sockets share the
%% same listen socket for sending/receiving data. This is different from
%% gen_tcp client sockets. 
%%------------------------------------------------------------------------------
close(#dtls_socket{role=Role, local_addr=Addr, local_port=Port,
                   client_addr=ClientAddr, client_port=ClientPort}) ->
    case dtls_socket_manager:get_server_pid(Addr, Port) of
        {ok, Pid} ->
            case Role of 
                R when R =:= server; R =:= client ->
                    dtls_socket_server:close(Pid, Addr, Port, Role),
                    dtls_socket_server:stop(Pid),
                    dtls_socket_manager:delete_server_port(Addr, Port);
                s_client ->
                    dtls_socket_server:close(Pid, ClientAddr, ClientPort, Role)
            end; 
        _ -> void 
    end,
    ok.

%%------------------------------------------------------------------------------
%% Internal Functions
%%------------------------------------------------------------------------------
%%------------------------------------------------------------------------------
%% Description: This function hold the calling process until there is new udp
%% client connects to server's transport address (ip + port) and return client
%% socket. 
%%------------------------------------------------------------------------------
accept_infinity_loop(CurrentPid, ServerPid, Socket, TRef) ->
    receive
        {timeout, TRef, timeout_for_check} -> 
            case dtls_socket_server:accept(ServerPid) of
                {ok, {ClientAddr, ClientPort}} ->
                    {ok, Socket#dtls_socket{role=s_client,
                             client_addr=ClientAddr, client_port=ClientPort}};
                {error, no_new_client} ->
                    NewTRef = erlang:start_timer(?ACCEPT_CHECK_TIMER, self(),
                        timeout_for_check),
                    accept_infinity_loop(CurrentPid, ServerPid, Socket, NewTRef)
            end;
        {'EXIT', CurrentPid, Reason}  ->
            {error, Reason};
        _Other ->
            accept_infinity_loop(CurrentPid, ServerPid, Socket, TRef)
    end.

%%------------------------------------------------------------------------------
%% Description: This function hold the calling process for limited time
%% specified by Timeout parameter or when there is new udp client connects
%% to server's transport address (ip + port) and return client socket. 
%%------------------------------------------------------------------------------
accept_timeout_loop(CurrentPid, ServerPid, Socket, T1Ref, T2Ref) ->
    receive
        {timeout, T1Ref, timeout_for_accept} ->
            % cancel the check out timer in case it is running
            erlang:cancel(T2Ref),  % cancel check timer
            {error, no_new_client};
        {timeout, T2Ref, timeout_for_check} -> 
            case dtls_socket_server:accept(ServerPid) of
                {ok, {ClientAddr, ClientPort}} ->
                    erlang:cancel(T1Ref),  % cancel the accept timer
                    {ok, Socket#dtls_socket{role=s_client,
                             client_addr=ClientAddr, client_port=ClientPort}};
                {error, no_new_client} ->
                    NewT2Ref = erlang:start_timer(
                        ?ACCEPT_CHECK_TIMER, self(), timeout_for_check),
                    accept_timeout_loop(CurrentPid, ServerPid, Socket, T1Ref, NewT2Ref)
            end;
        {'EXIT', CurrentPid, Reason} ->
            {error, Reason};
        _Other ->
            accept_timeout_loop(CurrentPid, ServerPid, Socket, T1Ref, T2Ref)
    end.

%%------------------------------------------------------------------------------
%% Description: Generic function finds the option value by its name.
%% option_not_founc will return if there is no such option in the option list. 
%%------------------------------------------------------------------------------
get_option(_Name, []) ->
    {error, option_not_found};
get_option(Name, [H|T]) ->
    case H of
        {Name, Value} ->
            Value;
        _ ->
            get_option(Name, T)
    end.

%%------------------------------------------------------------------------------
%% Description: Function to send binary data to client's transport address
%% (ip + port). 
%%------------------------------------------------------------------------------
internal_send(Pid, ClientAddr, ClientPort, Bin) ->
    try
        dtls_socket_server:send(Pid, ClientAddr, ClientPort, Bin)
    catch
        _:Reason -> {error, Reason}
    end.
