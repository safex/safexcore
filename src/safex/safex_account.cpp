//
// Created by amarko on 22.7.19..
//

#include <vector>
#include <iostream>
#include <stdint.h>

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_core.h"
#include "safex/command.h"
#include "safex_account.h"



namespace safex
{

  void safex_account_keys::set_device( hw::device &hwdev)  {
    m_device = &hwdev;
    MCDEBUG("device", "safex_account_keys::set_device device type: "<<typeid(hwdev).name());
  }

  crypto::secret_key safex_account_key_handler::generate(const crypto::secret_key &recovery_key, bool recover) {
    crypto::secret_key first = generate_keys(m_keys.m_public_key, m_keys.m_secret_key, recovery_key, recover);

    struct tm timestamp = {0};
    timestamp.tm_year = 2019 - 1900;  // year 2019
    timestamp.tm_mon = 6 - 1;  // month june
    timestamp.tm_mday = 8;  // 8th of june
    timestamp.tm_hour = 0;
    timestamp.tm_min = 0;
    timestamp.tm_sec = 0;

    if (recover)
    {
      m_creation_timestamp = mktime(&timestamp);
      if (m_creation_timestamp == (uint64_t)-1) // failure
        m_creation_timestamp = 0; // lowest value
    }
    else
    {
      m_creation_timestamp = time(NULL);
    }
    return first;
  }

  void safex_account_key_handler::create_from_device(const std::string &device_name)
  {

    hw::device &hwdev =  hw::get_device(device_name);
    m_keys.set_device(hwdev);
    hwdev.set_name(device_name);
    MCDEBUG("ledger", "device type: "<<typeid(hwdev).name());
    hwdev.init();
    hwdev.connect();
    crypto::secret_key dummy{};
    hwdev.get_secret_keys(dummy, m_keys.m_secret_key);
    struct tm timestamp = {0};
    timestamp.tm_year = 2019 - 1900;  // year 2019
    timestamp.tm_mon = 4 - 1;  // month april
    timestamp.tm_mday = 15;  // 15th of april
    timestamp.tm_hour = 0;
    timestamp.tm_min = 0;
    timestamp.tm_sec = 0;

    m_creation_timestamp = mktime(&timestamp);
    if (m_creation_timestamp == (uint64_t)-1) // failure
      m_creation_timestamp = 0; // lowest value
  }

  void safex_account_key_handler::create_from_keys(const crypto::secret_key &privatekey)
  {
    m_keys.m_secret_key = privatekey;

    crypto::secret_key_to_public_key(m_keys.m_secret_key, m_keys.m_public_key);

    struct tm timestamp = {0};
    timestamp.tm_year = 2019 - 1900;  // year 2019
    timestamp.tm_mon = 4 - 1;  // month april
    timestamp.tm_mday = 15;  // 15th of april
    timestamp.tm_hour = 0;
    timestamp.tm_min = 0;
    timestamp.tm_sec = 0;

    m_creation_timestamp = mktime(&timestamp);
    if (m_creation_timestamp == (uint64_t)-1) // failure
      m_creation_timestamp = 0; // lowest value
  }



  bool parse_safex_account_key(const cryptonote::txout_target_v &txout, crypto::public_key& pkey)
  {
    const cryptonote::txout_to_script &out = boost::get<cryptonote::txout_to_script>(txout);
    CHECK_AND_ASSERT_MES(out.output_type == static_cast<uint8_t>(cryptonote::tx_out_type::out_safex_account), false, "Parsing account key from non account output");
    safex::create_account_data account{};
    const cryptonote::blobdata accblob(std::begin(out.data), std::end(out.data));
    if (!cryptonote::parse_and_validate_from_blob(accblob, account))
    {
      ASSERT_MES_AND_THROW("Failed to parse and validate account from blob");
    }

    pkey = account.pkey;
    return true;
  }

  bool check_safex_account_signature(const crypto::hash &tx_prefix_hash, const crypto::public_key &sender_safex_account_key, const crypto::signature &signature)
  {
    return crypto::check_signature(tx_prefix_hash, sender_safex_account_key, signature) ? 1 : 0;
  }

}
