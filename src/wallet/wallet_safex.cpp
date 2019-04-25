#include <numeric>
#include <random>
#include <tuple>
#include <boost/format.hpp>
#include <boost/optional/optional.hpp>
#include <boost/utility/value_init.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/split.hpp>
#include "include_base_utils.h"
using namespace epee;

#include "cryptonote_config.h"
#include "wallet.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "misc_language.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "common/boost_serialization_helper.h"
#include "common/command_line.h"
#include "common/threadpool.h"
#include "profile_tools.h"
#include "crypto/crypto.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "cryptonote_basic/blobdatatype.h"
#include "mnemonics/electrum-words.h"
#include "common/i18n.h"
#include "common/util.h"
#include "common/apply_permutation.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "common/json_util.h"
#include "memwipe.h"
#include "common/base58.h"
#include "common/dns_utils.h"
#include "ringdb.h"

extern "C"
{
#include "crypto/keccak.h"
#include "crypto/crypto-ops.h"
}
using namespace std;
using namespace crypto;
using namespace cryptonote;

namespace tools
{
    std::vector<wallet::pending_tx> wallet::create_lock_transaction(
        std::vector<cryptonote::tx_destination_entry> dsts, 
        const size_t fake_outs_count, 
        const uint64_t unlock_time, 
        uint32_t priority, 
        const std::vector<uint8_t>& extra, 
        uint32_t subaddr_account, 
        std::set<uint32_t> subaddr_indices, 
        bool trusted_daemon)
    {
        return std::vector<wallet::pending_tx>{};
    }   

//-----------------------------------------------------------------------------------------------------------------
    std::vector<wallet::pending_tx> wallet::create_unlock_transaction(
        std::vector<cryptonote::tx_destination_entry> dsts, 
        const size_t fake_outs_count, 
        const uint64_t unlock_time, 
        uint32_t priority, 
        const std::vector<uint8_t>& extra, 
        uint32_t subaddr_account, 
        std::set<uint32_t> subaddr_indices, 
        bool trusted_daemon)
    {
        return std::vector<wallet::pending_tx>{};
    }
//-----------------------------------------------------------------------------------------------------------------
    std::vector<wallet::pending_tx> wallet::create_donation_transaction(
        std::vector<cryptonote::tx_destination_entry> dsts, 
        const size_t fake_outs_count, 
        const uint64_t unlock_time, 
        uint32_t priority, 
        const std::vector<uint8_t>& extra, 
        uint32_t subaddr_account, 
        std::set<uint32_t> subaddr_indices, 
        bool trusted_daemon)
    {
        return std::vector<wallet::pending_tx>{};
    }

}