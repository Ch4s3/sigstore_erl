.PHONY: all compile test check escript fmt
all: check escript
compile: ; rebar3 compile
test: ; rebar3 ct
check: compile ; rebar3 xref && rebar3 dialyzer && rebar3 ct
escript: ; rebar3 escriptize
fmt: ; rebar3 fmt
