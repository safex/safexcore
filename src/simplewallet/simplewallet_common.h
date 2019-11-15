#pragma once
#include <fstream>
#include <ctype.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/regex.hpp>
#include "include_base_utils.h"
#include "common/i18n.h"
#include "common/command_line.h"
#include "common/util.h"
#include "common/dns_utils.h"
#include "common/base58.h"
#include "common/scoped_message_writer.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "simplewallet.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "storages/http_abstract_invoke.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "crypto/crypto.h"  // for crypto::secret_key definition
#include "mnemonics/electrum-words.h"
#include "rapidjson/document.h"
#include "common/json_util.h"
#include "ringct/rctSigs.h"
#include "version.h"
#include <stdexcept>
#include <array>

#undef SAFEX_DEFAULT_LOG_CATEGORY
#define SAFEX_DEFAULT_LOG_CATEGORY "wallet.simplewallet"

#define EXTENDED_LOGS_FILE "wallet_details.log"

#define ENABLE_ADVANCED_OPTIONS 0 //some aditional features

#define MIN_RING_SIZE 7 // Used to inform user about min ring size -- does not track actual protocol

#define OUTPUT_EXPORT_FILE_MAGIC "Safex output export\003"

#define LOCK_IDLE_SCOPE() \
  bool auto_refresh_enabled = m_auto_refresh_enabled.load(std::memory_order_relaxed); \
  m_auto_refresh_enabled.store(false, std::memory_order_relaxed); \
  /* stop any background refresh, and take over */ \
  m_wallet->stop(); \
  m_idle_mutex.lock(); \
  while (m_auto_refresh_refreshing) \
    m_idle_cond.notify_one(); \
  m_idle_mutex.unlock(); \
/*  if (auto_refresh_run)*/ \
    /*m_auto_refresh_thread.join();*/ \
  boost::unique_lock<boost::mutex> lock(m_idle_mutex); \
  epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){ \
    m_auto_refresh_enabled.store(auto_refresh_enabled, std::memory_order_relaxed); \
  })

namespace po = boost::program_options;
typedef cryptonote::simple_wallet sw;

const std::array<const char* const, 5> allowed_priority_strings = {{"default", "unimportant", "normal", "elevated", "priority"}};
  const auto arg_wallet_file = wallet_args::arg_wallet_file();
  const command_line::arg_descriptor<std::string> arg_generate_new_wallet = {"generate-new-wallet", sw::tr("Generate new wallet and save it to <arg>"), ""};
  const command_line::arg_descriptor<std::string> arg_generate_from_device = {"generate-from-device", sw::tr("Generate new wallet from device and save it to <arg>"), ""};
  const command_line::arg_descriptor<std::string> arg_generate_from_view_key = {"generate-from-view-key", sw::tr("Generate incoming-only wallet from view key"), ""};
  const command_line::arg_descriptor<std::string> arg_generate_from_spend_key = {"generate-from-spend-key", sw::tr("Generate deterministic wallet from spend key"), ""};
  const command_line::arg_descriptor<std::string> arg_generate_from_keys = {"generate-from-keys", sw::tr("Generate wallet from private keys"), ""};
  const auto arg_generate_from_json = wallet_args::arg_generate_from_json();
  const command_line::arg_descriptor<std::string> arg_mnemonic_language = {"mnemonic-language", sw::tr("Language for mnemonic"), ""};
  const command_line::arg_descriptor<std::string> arg_electrum_seed = {"electrum-seed", sw::tr("Specify Electrum seed for wallet recovery/creation"), ""};
  const command_line::arg_descriptor<bool> arg_restore_deterministic_wallet = {"restore-deterministic-wallet", sw::tr("Recover wallet using Electrum-style mnemonic seed"), false};
  const command_line::arg_descriptor<bool> arg_non_deterministic = {"non-deterministic", sw::tr("Generate non-deterministic view and spend keys"), false};
  const command_line::arg_descriptor<bool> arg_trusted_daemon = {"trusted-daemon", sw::tr("Enable commands which rely on a trusted daemon"), false};
  const command_line::arg_descriptor<bool> arg_allow_mismatched_daemon_version = {"allow-mismatched-daemon-version", sw::tr("Allow communicating with a daemon that uses a different RPC version"), false};
  const command_line::arg_descriptor<uint64_t> arg_restore_height = {"restore-height", sw::tr("Restore from specific blockchain height"), 0};
  const command_line::arg_descriptor<bool> arg_do_not_relay = {"do-not-relay", sw::tr("The newly created transaction will not be relayed to the safex network"), false};
  const command_line::arg_descriptor<bool> arg_create_address_file = {"create-address-file", sw::tr("Create an address file for new wallets"), false};
  const command_line::arg_descriptor<std::string> arg_subaddress_lookahead = {"subaddress-lookahead", tools::wallet::tr("Set subaddress lookahead sizes to <major>:<minor>"), ""};
  const command_line::arg_descriptor<bool> arg_use_english_language_names = {"use-english-language-names", sw::tr("Display English language names"), false};

  const command_line::arg_descriptor< std::vector<std::string> > arg_command = {"command", ""};

#ifdef WIN32
  // Translate from CP850 to UTF-8;
  // std::getline for a Windows console returns a string in CP437 or CP850; as simplewallet,
  // like all of Safex, is assumed to work internally with UTF-8 throughout, even on Windows
  // (although only implemented partially), a translation to UTF-8 is needed for input.
  //
  // Note that if a program is started inside the MSYS2 shell somebody already translates
  // console input to UTF-8, but it's not clear how one could detect that in order to avoid
  // double-translation; this code here thus breaks UTF-8 input within a MSYS2 shell,
  // unfortunately.
  //
  // Note also that input for passwords is NOT translated, to remain compatible with any
  // passwords containing special characters that predate this switch to UTF-8 support.
  static std::string cp850_to_utf8(const std::string &cp850_str);
#endif

  std::string input_line(const std::string& prompt);

  boost::optional<tools::password_container> password_prompter(const char *prompt, bool verify);
  boost::optional<tools::password_container> default_password_prompter(bool verify);

  std::string interpret_rpc_response(bool ok, const std::string& status);
  tools::scoped_message_writer success_msg_writer(bool color = false);

  tools::scoped_message_writer message_writer(epee::console_colors color = epee::console_color_default, bool bright = false);
  tools::scoped_message_writer fail_msg_writer();

  bool parse_bool(const std::string& s, bool& result);

template <typename F>
  bool parse_bool_and_use(const std::string& s, F func)
  {
    bool r;
    if (parse_bool(s, r))
    {
      func(r);
      return true;
    }
    else
    {
      fail_msg_writer() << tr("invalid argument: must be either 0/1, true/false, y/n, yes/no");
      return false;
    }
  }

  const struct
  {
    const char *name;
    tools::wallet::RefreshType refresh_type;
  } refresh_type_names[] =
  {
    { "full", tools::wallet::RefreshFull },
    { "optimize-coinbase", tools::wallet::RefreshOptimizeCoinbase },
    { "optimized-coinbase", tools::wallet::RefreshOptimizeCoinbase },
    { "no-coinbase", tools::wallet::RefreshNoCoinbase },
    { "default", tools::wallet::RefreshDefault },
  };

  bool parse_refresh_type(const std::string &s, tools::wallet::RefreshType &refresh_type);

  std::string get_refresh_type_name(tools::wallet::RefreshType type);

  std::string get_version_string(uint32_t version);
  std::string oa_prompter(const std::string &url, const std::vector<std::string> &addresses, bool dnssec_valid);

  bool parse_subaddress_indices(const std::string& arg, std::set<uint32_t>& subaddr_indices);
  boost::optional<std::pair<uint32_t, uint32_t>> parse_subaddress_lookahead(const std::string& str);
  void handle_transfer_exception(const std::exception_ptr &e, bool trusted_daemon);
  bool check_file_overwrite(const std::string &filename);

bool parse_priority(const std::string& arg, uint32_t& priority);
