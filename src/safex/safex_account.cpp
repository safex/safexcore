//
// Created by amarko on 22.7.19..
//

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




}
