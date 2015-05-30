%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 1999-2013. All Rights Reserved.
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

%%

%%% Purpose : refactor udp transport to behaves like tcp mode for dtls
%%% data layer relaying. 

-ifndef(dtls_transport).
-define(dtls_transport, true).

-record(dtls_socket, {role        :: server | s_client | client,
                      local_addr  :: inet:ip_address(),
                      local_port  :: integer(),
                      client_addr :: inet:ip_address(),
                      client_port :: integer()
                     }).

-type dtls_socket() :: #dtls_socket{}.

-endif. % ifdef(dtls_transport)
