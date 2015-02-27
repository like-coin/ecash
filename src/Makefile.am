include Makefile.include

AM_CPPFLAGS += -I$(builddir)

noinst_LIBRARIES = \
  libecash_server.a \
  libecash_common.a \
  libecash_cli.a
if ENABLE_WALLET
noinst_LIBRARIES += libecash_wallet.a
endif

bin_PROGRAMS =

if BUILD_BITCOIND
  bin_PROGRAMS += ecashd
endif

if BUILD_BITCOIN_CLI
  bin_PROGRAMS += ecash-cli
endif

SUBDIRS = . $(BUILD_QT) $(BUILD_TEST)
DIST_SUBDIRS = . qt test
.PHONY: FORCE
# ecash core #
BITCOIN_CORE_H = \
  activemasternode.h \
  addrman.h \
  alert.h \
  allocators.h \
  base58.h bignum.h \
  bloom.h \
  chainparams.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coincontrol.h \
  coins.h \
  compat.h \
  core.h \
  crypter.h \
  darksend.h \
  db.h \
  hash.h \
  init.h \
  instantx.h \
  key.h \
  keepass.h \
  keystore.h \
  leveldbwrapper.h \
  limitedmap.h \
  main.h \
  masternode.h \
  masternodeconfig.h \
  miner.h \
  mruset.h \
  netbase.h \
  net.h \
  noui.h \
  protocol.h \
  rpcclient.h \
  rpcprotocol.h \
  rpcserver.h \
  script.h \
  serialize.h \
  sph_blake.h \
  sph_bmw.h \
  sph_cubehash.h \
  sph_echo.h \
  sph_groestl.h \
  sph_jh.h \
  sph_keccak.h \
  sph_luffa.h \
  sph_shavite.h \
  sph_simd.h \
  sph_skein.h \
  sph_types.h \
  spork.h \
  sync.h \
  threadsafety.h \
  tinyformat.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  uint256.h \
  util.h \
  version.h \
  walletdb.h \
  wallet.h

JSON_H = \
  json/json_spirit.h \
  json/json_spirit_error_position.h \
  json/json_spirit_reader.h \
  json/json_spirit_reader_template.h \
  json/json_spirit_stream_reader.h \
  json/json_spirit_utils.h \
  json/json_spirit_value.h \
  json/json_spirit_writer.h \
  json/json_spirit_writer_template.h

obj/build.h: FORCE
	@$(MKDIR_P) $(abs_top_builddir)/src/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
version.o: obj/build.h

libecash_server_a_SOURCES = \
  activemasternode.cpp \
  addrman.cpp \
  alert.cpp \
  bloom.cpp \
  checkpoints.cpp \
  coins.cpp \
  init.cpp \
  keystore.cpp \
  leveldbwrapper.cpp \
  main.cpp \
  miner.cpp \
  net.cpp \
  noui.cpp \
  rpcblockchain.cpp \
  rpcdarksend.cpp \
  rpcmining.cpp \
  rpcmisc.cpp \
  rpcnet.cpp \
  rpcrawtransaction.cpp \
  rpcserver.cpp \
  txdb.cpp \
  txmempool.cpp \
  $(JSON_H) \
  $(BITCOIN_CORE_H)

libecash_wallet_a_SOURCES = \
  activemasternode.cpp \
  db.cpp \
  crypter.cpp \
  rpcdump.cpp \
  rpcwallet.cpp \
  wallet.cpp \
  walletdb.cpp \
  keepass.cpp \
  $(BITCOIN_CORE_H)

libecash_common_a_SOURCES = \
  activemasternode.cpp \
  base58.cpp \
  allocators.cpp \
  chainparams.cpp \
  core.cpp \
  darksend.cpp \
  masternode.cpp \
  masternodeconfig.cpp \
  instantx.cpp \
  hash.cpp \
  key.cpp \
  netbase.cpp \
  protocol.cpp \
  rpcprotocol.cpp \
  script.cpp \
  sync.cpp \
  util.cpp \
  version.cpp \
  aes_helper.c \
  luffa.c \
  groestl.c \
  jh.c \
  echo.c \
  shavite.c \
  keccak.c \
  skein.c \
  spork.cpp \
  bmw.c \
  simd.c \
  cubehash.c \
  blake.c \
  $(BITCOIN_CORE_H)

if GLIBC_BACK_COMPAT
libecash_common_a_SOURCES += compat/glibc_compat.cpp
libecash_common_a_SOURCES += compat/glibcxx_compat.cpp
endif

libecash_cli_a_SOURCES = \
  rpcclient.cpp \
  $(BITCOIN_CORE_H)

nodist_libecash_common_a_SOURCES = $(top_srcdir)/src/obj/build.h
#

# ecashd binary #
ecashd_LDADD = \
  libecash_server.a \
  libecash_cli.a \
  libecash_common.a \
  $(LIBLEVELDB) \
  $(LIBMEMENV)
if ENABLE_WALLET
ecashd_LDADD += libecash_wallet.a
endif
ecashd_SOURCES = ecashd.cpp
#

if TARGET_WINDOWS
ecashd_SOURCES += bitcoind-res.rc
endif

AM_CPPFLAGS += $(BDB_CPPFLAGS)
ecashd_LDADD += $(BOOST_LIBS) $(BDB_LIBS)

# ecash-cli binary #
ecash_cli_LDADD = \
  libecash_cli.a \
  libecash_common.a \
  $(BOOST_LIBS)
ecash_cli_SOURCES = ecash-cli.cpp
#

if TARGET_WINDOWS
ecash_cli_SOURCES += bitcoin-cli-res.rc
endif

# NOTE: This dependency is not strictly necessary, but without it make may try to build both in parallel, which breaks the LevelDB build system in a race
leveldb/libleveldb.a: leveldb/libmemenv.a

leveldb/%.a:
	@echo "Building LevelDB ..." && $(MAKE) -C $(@D) $(@F) CXX="$(CXX)" \
	  CC="$(CC)" PLATFORM=$(TARGET_OS) AR="$(AR)" $(LEVELDB_TARGET_FLAGS) \
	  OPT="$(CXXFLAGS) $(CPPFLAGS)"

qt/bitcoinstrings.cpp: $(libecash_server_a_SOURCES) $(libecash_common_a_SOURCES) $(libecash_cli_a_SOURCES)
	@test -n $(XGETTEXT) || echo "xgettext is required for updating translations"
	@cd $(top_srcdir); XGETTEXT=$(XGETTEXT) share/qt/extract_strings_qt.py

CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a *.gcda *.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb Makefile.include

clean-local:
	-$(MAKE) -C leveldb clean
	rm -f leveldb/*/*.gcno leveldb/helpers/memenv/*.gcno
