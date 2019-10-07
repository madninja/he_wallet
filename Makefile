.PHONY: compile rel cover test typecheck doc ci

REBAR=./rebar3
SHORTSHA=`git rev-parse --short HEAD`
PKG_NAME_VER=${SHORTSHA}

OS_NAME=$(shell uname -s)

ifeq (${OS_NAME},FreeBSD)
make="gmake"
else
MAKE="make"
endif

compile:
	$(REBAR) escriptize
	cp _build/default/lib/enacl/priv/enacl_nif.so _build/default/bin
	cp _build/default/lib/erlang_sss/priv/erlang_sss.so _build/default/bin

shell:
	$(REBAR) shell

clean:
	$(REBAR) clean

cover:
	$(REBAR) cover

test:
	$(REBAR) as test do eunit,ct

ci:
	$(REBAR) do dialyzer,xref && $(REBAR) as test do eunit,ct,cover
	$(REBAR) covertool generate
	codecov --required -f _build/test/covertool/libp2p_streams.covertool.xml

typecheck:
	$(REBAR) dialyzer

doc:
	$(REBAR) edoc
