%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 2013-2015. All Rights Reserved.
%%
%% The contents of this file are subject to the Erlang Public License,
%% Version 1.1, (the "License"); you may not use this file except in
%% compliance with the License. You should have received a copy of the
%% Erlang Public License along with this software. If not, it can be
%% retrieved online at http://www.erlang.org/.
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and limitations
%% under the License.
%%
%% %CopyrightEnd%
%%
-module(dtls_connection).

%% Internal application API

-behaviour(gen_fsm).

-include("dtls_connection.hrl").
-include("dtls_handshake.hrl").
-include("ssl_alert.hrl").
-include("dtls_record.hrl").
-include("ssl_cipher.hrl").
-include("ssl_api.hrl").
-include("ssl_internal.hrl").
-include("ssl_srp.hrl").
-include_lib("public_key/include/public_key.hrl"). 

%% Internal application API

%% Setup
-export([start_fsm/8]).

%% State transition handling	 
-export([next_record/1, next_state/4]).

%% Handshake handling
-export([renegotiate/1, send_handshake/2, send_change_cipher/2]).

%% Alert and close handling
-export([send_alert/2, handle_own_alert/4, handle_close_alert/3,
	 handle_normal_shutdown/3, handle_unexpected_message/3]).

%% Data handling
-export([write_application_data/3, next_record_if_active/1]).

%% Called by tls_connection_sup
-export([start_link/7]). 

%% gen_fsm callbacks
-export([init/1, hello/2, certify/2, cipher/2,
	 abbreviated/2, connection/2, handle_event/3,
         handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

%%====================================================================
%% Internal application API
%%====================================================================
start_fsm(Role, Host, Port, Socket, {#ssl_options{erl_dist = false},_, undefined} = Opts,
	  User, {CbModule, _,_, _} = CbInfo, 
	  Timeout) -> 
    try 
	{ok, Pid} = dtls_connection_sup:start_child([Role, Host, Port, Socket, 
						     Opts, User, CbInfo]), 
	{ok, SslSocket} = ssl_connection:socket_control(?MODULE, Socket, Pid, CbModule),
	ok = ssl_connection:handshake(SslSocket, Timeout),
	{ok, SslSocket} 
    catch
	error:{badmatch, {error, _} = Error} ->
	    Error
    end;

start_fsm(Role, Host, Port, Socket, {#ssl_options{erl_dist = true},_, undefined} = Opts,
	  User, {CbModule, _,_, _} = CbInfo, 
	  Timeout) -> 
    try 
	{ok, Pid} = dtls_connection_sup:start_child_dist([Role, Host, Port, Socket, 
							  Opts, User, CbInfo]), 
	{ok, SslSocket} = ssl_connection:socket_control(?MODULE, Socket, Pid, CbModule),
	ok = ssl_connection:handshake(SslSocket, Timeout),
	{ok, SslSocket} 
    catch
	error:{badmatch, {error, _} = Error} ->
	    Error
    end.

send_handshake({finished, _} = Handshake,
               #state{dtls_version = Version, tls_handshake_history = Hist0,
                      socket = Socket, transport_cb = Transport,
                      connection_states = ConnectionStates0} = State0) ->
    {BinHandshake, ConnectionStates, Hist, _FragmentedHandshake} =
	encode_handshake(Handshake, Version, ConnectionStates0, Hist0),
    %% last step in SSL/TLS handshake, clean up the flight
    Transport:send(Socket, BinHandshake),
    delete_flight_if_active(State0#state{connection_states = ConnectionStates,
                                         tls_handshake_history = Hist});
send_handshake(Handshake, #state{dtls_version = Version,
				 tls_handshake_history = Hist0,
				 connection_states = ConnectionStates0} = State0) ->
    {BinHandshake, ConnectionStates, Hist, FragmentedHandshake} =
	encode_handshake(Handshake, Version, ConnectionStates0, Hist0),
    send_flight(BinHandshake, FragmentedHandshake,
                State0#state{connection_states = ConnectionStates,
                             tls_handshake_history = Hist}).

send_alert(Alert, #state{dtls_version = Version,
			 socket = Socket,
			 transport_cb = Transport,
			 connection_states = ConnectionStates0} = State0) ->
    {BinMsg, ConnectionStates} =
	ssl_alert:encode(Alert, Version, ConnectionStates0),
    Transport:send(Socket, BinMsg),
    State0#state{connection_states = ConnectionStates}.

send_change_cipher(Msg, #state{connection_states = ConnectionStates0,
			       socket = Socket,
			       % negotiated_version = Version,
                               dtls_version = Version,
			       transport_cb = Transport} = State0) ->
    {BinChangeCipher, ConnectionStates} =
	encode_change_cipher(Msg, Version, ConnectionStates0),
    Transport:send(Socket, BinChangeCipher),
    State0#state{connection_states = ConnectionStates}.

%%====================================================================
%% tls_connection_sup API
%%====================================================================

%%--------------------------------------------------------------------
-spec start_link(atom(), host(), inet:port_number(), port(), list(), pid(), tuple()) ->
    {ok, pid()} | ignore |  {error, reason()}.
%%
%% Description: Creates a gen_fsm process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this function
%% does not return until Module:init/1 has returned.  
%%--------------------------------------------------------------------
start_link(Role, Host, Port, Socket, Options, User, CbInfo) ->
    {ok, proc_lib:spawn_link(?MODULE, init, [[Role, Host, Port, Socket, Options, User, CbInfo]])}.

init([Role, Host, Port, Socket, {SSLOpts0, _, _} = Options,  User, CbInfo]) ->
    process_flag(trap_exit, true),
    State0 =  initial_state(Role, Host, Port, Socket, Options, User, CbInfo),
    Handshake = ssl_handshake:init_handshake_history(),
    TimeStamp = calendar:datetime_to_gregorian_seconds({date(), time()}),
    try ssl_config:init(SSLOpts0, Role) of
	{ok, Ref, CertDbHandle, FileRefHandle, CacheHandle,  CRLDbInfo, OwnCert, Key, DHParams} ->
	    Session = State0#state.session,
	    State = State0#state{
		      tls_handshake_history = Handshake,
		      session = Session#session{own_certificate = OwnCert,
						time_stamp = TimeStamp},
		      file_ref_db = FileRefHandle,
		      cert_db_ref = Ref,
		      cert_db = CertDbHandle,
		      crl_db = CRLDbInfo,
		      session_cache = CacheHandle,
		      private_key = Key,
		      diffie_hellman_params = DHParams},
	    gen_fsm:enter_loop(?MODULE, [], hello, State, get_timeout(State))
    catch
	throw:Error ->
	    gen_fsm:enter_loop(?MODULE, [], error, {Error,State0}, get_timeout(State0))
    end.

%%--------------------------------------------------------------------
%% Description:There should be one instance of this function for each
%% possible state name. Whenever a gen_fsm receives an event sent
%% using gen_fsm:send_event/2, the instance of this function with the
%% same name as the current state name StateName is called to handle
%% the event. It is also called if a timeout occurs.
%%
hello(start, #state{host = Host, port = Port, role = client,
		    ssl_options = SslOpts,
		    session = #session{own_certificate = Cert} = Session0,
		    session_cache = Cache, session_cache_cb = CacheCb,
		    transport_cb = Transport, socket = Socket,
		    connection_states = ConnectionStates0,
		    renegotiation = {Renegotiation, _}} = State0) ->
    Hello = dtls_handshake:client_hello(Host, Port, ConnectionStates0, SslOpts,
					Cache, CacheCb, Renegotiation, Cert),
    
    Version = Hello#client_hello.client_version,
    Handshake0 = ssl_handshake:init_handshake_history(),
    {BinMsg, ConnectionStates, Handshake, FragmentedHandshake} =
        encode_handshake(Hello, Version, ConnectionStates0, Handshake0),
    Transport:send(Socket, BinMsg),
    State1 = send_flight(BinMsg, FragmentedHandshake,
                         State0#state{dtls_version = Version,
                             connection_states = ConnectionStates,
                             session = Session0#session{
                                 session_id = Hello#client_hello.session_id},
                             tls_handshake_history = Handshake}),
    {Record, State} = next_record(State1),
    next_state(hello, hello, Record, State);

hello(Hello = #client_hello{client_version = ClientVersion,
			    extensions = #hello_extensions{hash_signs = HashSigns}},
      State = #state{connection_states = ConnectionStates0,
		     port = Port, session = #session{own_certificate = Cert} = Session0,
		     renegotiation = {Renegotiation, _},
		     session_cache = Cache,
		     session_cache_cb = CacheCb,
		     ssl_options = SslOpts,
                     socket = Socket,
                     negotiated_protocol = CurrentProtocol,
                     tls_handshake_history = Hist0}) ->
    case dtls_handshake:hello(Hello, SslOpts, {Port, Session0, Cache, CacheCb,
					      ConnectionStates0, Cert, Socket}, Renegotiation) of
        {Version, {Type, Session},
	 ConnectionStates, Protocol0,
	 #hello_extensions{ec_point_formats = EcPointFormats,
			   elliptic_curves = EllipticCurves} = ServerHelloExt} ->
            Protocol = case Protocol0 of
                undefined -> CurrentProtocol;
                _ -> Protocol0
            end,
            HashSign = ssl_handshake:select_hashsign(HashSigns, Cert, dtls_v1:corresponding_tls_version(Version)),
            ssl_connection:hello({common_client_hello, Type, ServerHelloExt, HashSign},
				 State#state{connection_states  = ConnectionStates,
                                             dtls_version = Version,
                                             negotiated_version = dtls_v1:corresponding_tls_version(Version),
					     session = Session,
                                             negotiated_protocol = Protocol,
					     client_ecc = {EllipticCurves, EcPointFormats}}, ?MODULE);

        {verifying, HelloVerifyRequest} ->
            {Encoded, ConnStates, _, FragmentedHandshake} =
                encode_handshake(HelloVerifyRequest, ClientVersion, ConnectionStates0, Hist0),
            %% DTLS RFC Sec 4.2.6
            %% In cases where the cookie exchange is used, the initial ClientHello and HelloVerifyRequest
            %% MUST NOT be included in the CertificateVerify or Finished MAC computations.
            State0 = send_flight(Encoded, FragmentedHandshake, State#state{connection_states = ConnStates}),
            next_state(hello, hello, no_record,
                       State0#state{dtls_version=ClientVersion,
                                    tls_handshake_history = ssl_handshake:init_handshake_history()});

        #alert{} = Alert ->
            handle_own_alert(Alert, ClientVersion, hello, State)
    end;
hello(Hello,
      #state{host = Host, port = Port,
             session = #session{own_certificate = Cert} = Session0,
             session_cache = Cache, session_cache_cb = CacheCb,
             connection_states = ConnectionStates0,
             dtls_version = ReqVersion,
	     role = client,
	     renegotiation = {Renegotiation, _},
	     ssl_options = SslOptions} = State0) ->
    case dtls_handshake:hello(Hello, SslOptions, {Port, Session0, Cache, CacheCb,
                                              ConnectionStates0, Cert, Host}, Renegotiation) of
	#alert{} = Alert ->
	    handle_own_alert(Alert, ReqVersion, hello, State0);
        #client_hello{client_version = Version, session_id = NewId} = NewCliHello ->
            Handshake0 = ssl_handshake:init_handshake_history(),
            State1 = send_handshake(NewCliHello, State0#state{dtls_version = Version,
                                                    session = Session0#session{session_id=NewId},
                                                    tls_handshake_history = Handshake0}),
            {Record, State} = next_record(State1),
            next_state(hello, hello, Record, State);
	{Version, NewId, ConnectionStates, ProtocolExt, Protocol} ->
	    ssl_connection:handle_session(Hello, dtls_v1:corresponding_tls_version(Version),
					  NewId, ConnectionStates, ProtocolExt, Protocol,
                                          State0#state{dtls_version = Version})
    end;

hello(Msg, State) ->
    ssl_connection:hello(Msg, State, ?MODULE).

abbreviated(Msg, State) ->
    ssl_connection:abbreviated(Msg, State, ?MODULE).

certify(Msg, State) ->
    ssl_connection:certify(Msg, State, ?MODULE).

cipher(Msg, State) ->
     ssl_connection:cipher(Msg, State, ?MODULE).

connection(#hello_request{}, #state{host = Host, port = Port,
				    session = #session{own_certificate = Cert} = Session0,
				    session_cache = Cache, session_cache_cb = CacheCb,
				    ssl_options = SslOpts,
				    connection_states = ConnectionStates0,
				    renegotiation = {Renegotiation, _}} = State0) ->
    Hello = dtls_handshake:client_hello(Host, Port, ConnectionStates0, SslOpts,
					Cache, CacheCb, Renegotiation, Cert),
    %% TODO DTLS version State1 = send_handshake(Hello, State0),
    State1 = State0,
    {Record, State} =
	next_record(
	  State1#state{session = Session0#session{session_id
						  = Hello#client_hello.session_id}}),
    next_state(connection, hello, Record, State);

connection(#client_hello{} = Hello, #state{role = server, allow_renegotiate = true} = State) ->
    %% Mitigate Computational DoS attack
    %% http://www.educatedguesswork.org/2011/10/ssltls_and_computational_dos.html
    %% http://www.thc.org/thc-ssl-dos/ Rather than disabling client
    %% initiated renegotiation we will disallow many client initiated
    %% renegotiations immediately after each other.
    erlang:send_after(?WAIT_TO_ALLOW_RENEGOTIATION, self(), allow_renegotiate),
    hello(Hello, State#state{allow_renegotiate = false});

connection(#client_hello{}, #state{role = server, allow_renegotiate = false} = State0) ->
    Alert = ?ALERT_REC(?WARNING, ?NO_RENEGOTIATION),
    State = send_alert(Alert, State0),
    ssl_connection:next_state_connection(connection, State);
  
connection(Msg, State) ->
     ssl_connection:connection(Msg, State, tls_connection).

%%--------------------------------------------------------------------
%% Description: Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_all_state_event/2, this function is called to handle
%% the event. Not currently used!
%%--------------------------------------------------------------------
handle_event(_Event, StateName, State) ->
    {next_state, StateName, State, get_timeout(State)}.

%%--------------------------------------------------------------------
%% Description: Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_all_state_event/2,3, this function is called to handle
%% the event.
%%--------------------------------------------------------------------
handle_sync_event(Event, From, StateName, State) ->
    ssl_connection:handle_sync_event(Event, From, StateName, State).

%%--------------------------------------------------------------------
%% Description: This function is called by a gen_fsm when it receives any
%% other message than a synchronous or asynchronous event
%% (or a system message).
%%--------------------------------------------------------------------

%% raw data from socket, unpack records
handle_info({Protocol, _, Data}, StateName,
            #state{data_tag = Protocol} = State0) ->
    case next_dtls_record(Data, State0) of
        {Record, State} ->
            next_state(StateName, StateName, Record, State);
        #alert{} = Alert ->
            handle_normal_shutdown(Alert, StateName, State0),
            {stop, {shutdown, own_alert}, State0}
    end;

handle_info({CloseTag, Socket}, StateName,
            #state{socket = Socket, close_tag = CloseTag,
		   dtls_version = _Version} = State) ->
    handle_normal_shutdown(?ALERT_REC(?FATAL, ?CLOSE_NOTIFY), StateName, State),
    {stop, {shutdown, transport_closed}, State};

handle_info({timeout, _Ref, flight_retransmit_timeout}, StateName,
            #state{socket = Socket, transport_cb = Transport,
                   dtls_version = Version,
                   connection_states = ConnectionStates0,
                   flight = #flight{last_retransmit = Retrans,
                                    buffer = SentQueue,
                                    state = FlightState} = Flight} = State) ->
    case FlightState of
        ?FLIGHT_WAITING_STATE ->
            if
                Retrans =< 32 ->
                    {done, ConnectionStates} = resend(Socket, Transport, Version, ConnectionStates0, SentQueue),
                    RetransTmrRef = erlang:start_timer(Retrans*2000, self(),
                                        flight_retransmit_timeout),
                    {next_state, StateName, State#state{connection_states = ConnectionStates,
                         flight = Flight#flight{last_retransmit = Retrans * 2,
                                                msl_timer = RetransTmrRef}}, get_timeout(State)};
                true ->
                    %% failed the handshake for this client
                    handle_normal_shutdown(#alert{}, StateName, State),
                    {stop, {shutdown, own_alert}, State}
           end;
        _ ->
           {next_state, StateName, State, get_timeout(State)}
    end;

handle_info(Msg, StateName, State) ->
    ssl_connection:handle_info(Msg, StateName, State).

%%--------------------------------------------------------------------
%% Description:This function is called by a gen_fsm when it is about
%% to terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_fsm terminates with
%% Reason. The return value is ignored.
%%--------------------------------------------------------------------
terminate(Reason, StateName, #state{socket=Socket, transport_cb=Transport}=State) ->
    ssl_connection:terminate(Reason, StateName, State),
    Transport:close(Socket).

%%--------------------------------------------------------------------
%% code_change(OldVsn, StateName, State, Extra) -> {ok, StateName, NewState}
%% Description: Convert process state when code is changed
%%--------------------------------------------------------------------
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
encode_handshake(Handshake, Version, ConnectionStates0, Hist0) ->
    {MessageSeq, ConnectionStates1} = sequence(ConnectionStates0),
    {EncHandshake, FragmentedHandshake} = dtls_handshake:encode_handshake(Handshake, Version,
								      MessageSeq),
    Hist = update_handshake_history(Hist0, EncHandshake),
    {Encoded, ConnectionStates} =
        dtls_record:encode_handshake(FragmentedHandshake, 
				     Version, ConnectionStates1),
    {Encoded, ConnectionStates, Hist, FragmentedHandshake}.

next_record(#state{%%flight = #flight{state = finished}, 
		   protocol_buffers =
		       #protocol_buffers{dtls_packets = [], dtls_cipher_texts = [CT | Rest]}
		   = Buffers,
		   connection_states = ConnStates0} = State) ->
    case dtls_record:decode_cipher_text(CT, ConnStates0) of
	{Plain, ConnStates} ->		      
	    {Plain, State#state{protocol_buffers =
				    Buffers#protocol_buffers{dtls_cipher_texts = Rest},
				connection_states = ConnStates}};
	#alert{} = Alert ->
	    {Alert, State}
    end;
next_record(#state{socket = Socket,
		   transport_cb = Transport} = State) -> %% when FlightState =/= finished
    ssl_socket:setopts(Transport, Socket, [{active,once}]),
    {no_record, State};


next_record(State) ->
    {no_record, State}.

next_state(Current,_, #alert{} = Alert, #state{dtls_version = Version} = State) ->
    handle_own_alert(Alert, Version, Current, State);

next_state(_,Next, no_record, State) ->
    {next_state, Next, State, get_timeout(State)};

next_state(_,Next, #ssl_tls{type = ?ALERT, fragment = EncAlerts}, State) ->
    Alerts = ssl_alert:decode(EncAlerts),
    ssl_connection:handle_alerts(Alerts,  {next_state, Next, State, get_timeout(State)});

next_state(Current, Next, #ssl_tls{type = ?HANDSHAKE} = Record,
	   State0 = #state{protocol_buffers =
			       #protocol_buffers{dtls_handshake_buffer = Buf0,
                                                 dtls_cipher_texts = PendingRecords} = Buffers,
			   dtls_version = Version}) ->
    Handle = 
   	fun({#hello_request{} = Packet, _}, {next_state, connection = SName, State}) ->
   		%% This message should not be included in handshake
   		%% message hashes. Starts new handshake (renegotiation)
		Hs0 = ssl_handshake:init_handshake_history(),
		?MODULE:SName(Packet, State#state{tls_handshake_history=Hs0,
   						  renegotiation = {true, peer}});
   	   ({#hello_request{} = Packet, _}, {next_state, SName, State}) ->
   		%% This message should not be included in handshake
   		%% message hashes. Already in negotiation so it will be ignored!
   		?MODULE:SName(Packet, State);
	   ({#client_hello{} = Packet, Raw}, {next_state, connection = SName, State}) ->
		Version = Packet#client_hello.client_version,
		Hs0 = ssl_handshake:init_handshake_history(),
		Hs1 = update_handshake_history(Hs0, Raw),
		?MODULE:SName(Packet, State#state{tls_handshake_history=Hs1,
   						  renegotiation = {true, peer}});
	   ({Packet, Raw}, {next_state, SName, State = #state{tls_handshake_history=Hs0}}) ->
		Hs1 = update_handshake_history(Hs0, Raw),
		?MODULE:SName(Packet, State#state{tls_handshake_history=Hs1});
   	   (_, StopState) -> StopState
   	end,
    try
        %% Record is dtls_record defined in dtls_record.hrl
        %% get_dtls_handshake() method will parse the dtls record into dtls messages,
        %% leftover bytes are stored in Buf.
	{Packets, Buf} = dtls_handshake:get_dtls_handshake(Record,Buf0),
	State = State0#state{protocol_buffers =
				 Buffers#protocol_buffers{dtls_packets = Packets,
							  dtls_handshake_buffer = Buf}},
        case Packets of
            retransmit ->
                %% check next record if there is any
                next_state(Current, Next, no_record, State);
            [] ->
                next_state(Current, Next, no_record, State);
            _ ->
                %% handshake packet received, needs to stop flight if it is active
                State1 = delete_flight_if_active(State),
	        handle_dtls_handshake(Handle, Next, State1)
        end
    catch throw:#alert{} = Alert ->
	    handle_own_alert(Alert, Version, Current, State0)
    end;

next_state(_, StateName, #ssl_tls{type = ?APPLICATION_DATA, fragment = Data}, State0) ->
    %% Simplify for now to avoid dialzer warnings before implementation is  compleate
    case ssl_connection:read_application_data(Data, State0) of
        Stop = {stop,_,_} ->
            Stop;
        {Record, State} ->
            next_state(StateName, StateName, Record, State)
    end;
	
next_state(Current, Next, #ssl_tls{type = ?CHANGE_CIPHER_SPEC, fragment = <<1>>} = 
 	   _ChangeCipher, 
 	   #state{connection_states = ConnectionStates0} = State0) ->
    ConnectionStates1 =
	ssl_record:activate_pending_connection_state(ConnectionStates0, read),
    {Record, State} = next_record(State0#state{connection_states = ConnectionStates1}),
    next_state(Current, Next, Record, State#state{expecting_finished = true});
next_state(Current, Next, #ssl_tls{type = _Unknown}, State0) ->
    %% Ignore unknown type 
    {Record, State} = next_record(State0),
    next_state(Current, Next, Record, State).

%handle_dtls_handshake(_Handle, _StateName,
%		     #state{protocol_buffers =
%				#protocol_buffers{dtls_packets = []}}) ->
%    void;

handle_dtls_handshake(Handle, StateName,
		     #state{protocol_buffers =
				#protocol_buffers{dtls_packets = [Packet]} = Buffers} = State) ->
    FsmReturn = {next_state, StateName, State#state{protocol_buffers =
							Buffers#protocol_buffers{dtls_packets = []}}},
    Handle(Packet, FsmReturn);

handle_dtls_handshake(Handle, StateName,
		     #state{protocol_buffers =
				#protocol_buffers{dtls_packets = [Packet | Packets]} = Buffers} =
			 State0) ->
    FsmReturn = {next_state, StateName, State0#state{protocol_buffers =
							 Buffers#protocol_buffers{dtls_packets =
										      Packets}}},
    case Handle(Packet, FsmReturn) of
	{next_state, NextStateName, State, _Timeout} ->
	    handle_dtls_handshake(Handle, NextStateName, State);
	{stop, _,_} = Stop ->
	    Stop
    end.


send_flight(BinFragments, FragmentedFragments, #state{transport_cb = Transport, socket = Socket,
			      flight = #flight{buffer = SentQueue } = Flight} = State) ->
    Transport:send(Socket, BinFragments),
    %% Start retransmission
    case SentQueue of
        [] ->
            %% first message in the queue
            RetransTimerRef=erlang:start_timer(1000, self(), flight_retransmit_timeout),
            State#state{flight = Flight#flight{
                            last_retransmit = 1,  %% rfc 6289
                            msl_timer = RetransTimerRef,
                            buffer = FragmentedFragments,
                            state = ?FLIGHT_WAITING_STATE}};
        _ ->
            %% already has messages in the queue
            State#state{flight = Flight#flight{
                            buffer = lists:append(SentQueue, FragmentedFragments),
                            state = ?FLIGHT_WAITING_STATE}}
    end.

handle_own_alert(Alert, Version, StateName,
                 #state{transport_cb = Transport,
                        socket = Socket,
                        connection_states = ConnectionStates,
                        ssl_options = SslOpts} = State) ->
    try %% Try to tell the other side
        {BinMsg, _} =
        ssl_alert:encode(Alert, Version, ConnectionStates),
        Transport:send(Socket, BinMsg)
    catch _:_ ->  %% Can crash if we are in a uninitialized state
            ignore
    end,
    try %% Try to tell the local user
        ssl_connection:log_alert(SslOpts#ssl_options.log_alert, StateName, Alert),
        handle_normal_shutdown(Alert,StateName, State)
    catch _:_ ->
            ok
    end,
    {stop, {shutdown, own_alert}, State}.


handle_normal_shutdown(Alert, _, #state{socket = Socket,
                                        transport_cb = Transport,
                                        start_or_recv_from = StartFrom,
                                        tracker = Tracker,
                                        role = Role, renegotiation = {false, first}}) ->
    ssl_connection:alert_user(Transport, Tracker,Socket, StartFrom, Alert, Role);

handle_normal_shutdown(Alert, StateName, #state{socket = Socket,
                                                socket_options = Opts,
                                                transport_cb = Transport,
                                                user_application = {_Mon, Pid},
                                                tracker = Tracker,
                                                start_or_recv_from = RecvFrom, role = Role}) ->
    ssl_connection:alert_user(Transport, Tracker, Socket, StateName, Opts, Pid, RecvFrom, Alert, Role).

handle_unexpected_message(Msg, Info, #state{negotiated_version = Version} = State) ->
    Alert = ?ALERT_REC(?FATAL, ?UNEXPECTED_MESSAGE),
    handle_own_alert(Alert, Version, {Info, Msg}, State).

encode_change_cipher(#change_cipher_spec{}, Version, ConnectionStates) -> 
    dtls_record:encode_change_cipher_spec(Version, ConnectionStates).

initial_state(Role, Host, Port, Socket, {SSLOptions, SocketOptions, _}, User,
	      {CbModule, DataTag, CloseTag, ErrorTag}) ->
    ConnectionStates = ssl_record:init_connection_states(Role),
    
    SessionCacheCb = case application:get_env(ssl, session_cb) of
			 {ok, Cb} when is_atom(Cb) ->
			    Cb;
			 _  ->
			     ssl_session_cache
		     end,
    
    Monitor = erlang:monitor(process, User),

    #state{socket_options = SocketOptions,
	   %% We do not want to save the password in the state so that
	   %% could be written in the clear into error logs.
	   ssl_options = SSLOptions#ssl_options{password = undefined},	   
	   session = #session{is_resumable = new},
	   transport_cb = CbModule,
	   data_tag = DataTag,
	   close_tag = CloseTag,
	   error_tag = ErrorTag,
	   role = Role,
	   host = Host,
	   port = Port,
	   socket = Socket,
	   connection_states = ConnectionStates,
	   protocol_buffers = #protocol_buffers{},
	   user_application = {Monitor, User},
	   user_data_buffer = <<>>,
	   session_cache_cb = SessionCacheCb,
	   renegotiation = {false, first},
	   start_or_recv_from = undefined,
	   send_queue = queue:new(),
	   protocol_cb = ?MODULE,
           flight = #flight{buffer = []}
	  }.

%% changed by yhy
%% dtls_cipher_texts stores every dtls record in a list
next_dtls_record(Data, #state{protocol_buffers = #protocol_buffers{dtls_record_buffer = Buf0,
                                                dtls_cipher_texts = CT0} = Buffers} = State0) ->
    case dtls_record:get_dtls_records(Data, Buf0) of
        {Records, Buf1} ->
            CT1 = CT0 ++ Records,
            next_record(State0#state{protocol_buffers =
                                         Buffers#protocol_buffers{dtls_record_buffer = Buf1,
                                                                  dtls_cipher_texts = CT1}});
        #alert{} = Alert ->
            Alert
    end.

get_timeout(#state{ssl_options=#ssl_options{hibernate_after = undefined}}) ->
    infinity;
get_timeout(#state{ssl_options=#ssl_options{hibernate_after = HibernateAfter}}) ->
    HibernateAfter.

sequence(#connection_states{msg_sequence = Seq} = ConnectionStates) ->
    {Seq, ConnectionStates#connection_states{msg_sequence = Seq + 1}}.

next_record_if_active(State =
                      #state{socket_options =
                             #socket_options{active = false}}) ->
    {no_record ,State};

next_record_if_active(State) ->
    next_record(State).

%% clean up previous flight if it exists
delete_flight_if_active(#state{flight = Flight} = State) ->
    if
        Flight#flight.buffer =/= [] ->
            erlang:cancel_timer(Flight#flight.msl_timer),
            State#state{flight = Flight#flight{buffer = []}};
        true ->
            State
    end.

time_to_renegotiate(_Data,
                    #connection_states{current_write =
                                           #connection_state{sequence_number = Num}},
                    RenegotiateAt) ->
    %% We could do test:
    %% is_time_to_renegotiate((erlang:byte_size(_Data) div ?MAX_PLAIN_TEXT_LENGTH) + 1, RenegotiateAt),
    %% but we chose to have a some what lower renegotiateAt and a much cheaper test
    is_time_to_renegotiate(Num, RenegotiateAt).

is_time_to_renegotiate(N, M) when N < M->
    false;
is_time_to_renegotiate(_,_) ->
    true.

renegotiate(#state{role = client} = State) ->
    %% Handle same way as if server requested
    %% the renegotiation
    Hs0 = ssl_handshake:init_handshake_history(),
    connection(#hello_request{}, State#state{tls_handshake_history = Hs0});
renegotiate(#state{role = server,
                   socket = Socket,
                   transport_cb = Transport,
                   negotiated_version = Version,
                   connection_states = ConnectionStates0} = State0) ->
    HelloRequest = ssl_handshake:hello_request(),
    Frag = tls_handshake:encode_handshake(HelloRequest, Version),
    Hs0 = ssl_handshake:init_handshake_history(),
    {BinMsg, ConnectionStates} =
        ssl_record:encode_handshake(Frag, Version, ConnectionStates0),
    Transport:send(Socket, BinMsg),
    {Record, State} = next_record(State0#state{connection_states =
                                               ConnectionStates,
                                               tls_handshake_history = Hs0}),
    next_state(connection, hello, Record, State#state{allow_renegotiate = true}).

handle_close_alert(Data, StateName, State0) ->
    case next_dtls_record(Data, State0) of
        {#ssl_tls{type = ?ALERT, fragment = EncAlerts}, State} ->
            [Alert|_] = ssl_alert:decode(EncAlerts),
            handle_normal_shutdown(Alert, StateName, State);
        _ ->
            ok
    end.

write_application_data(Data0, From,
                       #state{socket = Socket,
                              dtls_version = Version,
                              transport_cb = Transport,
                              connection_states = ConnectionStates0,
                              send_queue = SendQueue,
                              socket_options = SockOpts,
                              ssl_options = #ssl_options{renegotiate_at = RenegotiateAt}} = State) ->
    Data = ssl_connection:encode_packet(Data0, SockOpts),

    case time_to_renegotiate(Data, ConnectionStates0, RenegotiateAt) of
        true ->
            renegotiate(State#state{send_queue = queue:in_r({From, Data}, SendQueue),
                                    renegotiation = {true, internal}});
        false ->
            {Msgs, ConnectionStates} = ssl_record:encode_data(Data, Version, ConnectionStates0),
            Result = Transport:send(Socket, Msgs),
            {reply, Result,
             connection, State#state{connection_states = ConnectionStates}, get_timeout(State)}
    end.

%% provide a local version as ssl_handshake handles a special case for SSL v2
update_handshake_history({Handshake0, _Prev}, Data) ->
    {[Data|Handshake0], Handshake0}.

resend(Socket, Transport, Version, ConnectionStates0, []) ->
    {done, ConnectionStates0};
resend(Socket, Transport, Version, ConnectionStates0, [Handshake | T]) ->
    {Encoded, ConnectionStates} =
        dtls_record:encode_handshake(Handshake, Version, ConnectionStates0),
    Transport:send(Socket, Encoded),
    resend(Socket, Transport, Version, ConnectionStates, T).
