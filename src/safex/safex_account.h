//
// Created by amarko on 22.7.19..
//

#ifndef SAFEX_SAFEX_ACCOUNT_H
#define SAFEX_SAFEX_ACCOUNT_H


#include <string>

#include "device/device.hpp"
#include "crypto/crypto.h"
#include "serialization/keyvalue_serialization.h"

#include "safex_core.h"
#include "safex_account.h"

#undef SAFEX_DEFAULT_LOG_CATEGORY
#define SAFEX_DEFAULT_LOG_CATEGORY "safex_account"

namespace safex
{

  const int MAX_ACCOUNT_DATA_SIZE = 1024;

  struct safex_account_keys
  {
      crypto::public_key m_public_key;
      crypto::secret_key m_secret_key;
      hw::device *m_device = &hw::get_device("default");

    BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(m_public_key)
        KV_SERIALIZE(m_secret_key)
      END_KV_SERIALIZE_MAP()

      safex_account_keys &operator=(const safex_account_keys &) = default;

      hw::device &get_device() const;

      void set_device(hw::device &hwdev);


  };

  class safex_account_key_handler
  {
      safex_account_key_handler() {}

      crypto::secret_key generate(const crypto::secret_key &recovery_key = crypto::secret_key(), bool recover = false);

      void create_from_device(const std::string &device_name);

      void create_from_keys(const crypto::secret_key &privatekey);

      const safex_account_keys &get_keys() const;

      hw::device &get_device() const
      { return m_keys.get_device(); }

      void set_device(hw::device &hwdev)
      { m_keys.set_device(hwdev); }

      uint64_t get_createtime() const
      { return m_creation_timestamp; }

      void set_createtime(uint64_t val)
      { m_creation_timestamp = val; }

      template<class t_archive>
      inline void serialize(t_archive &a, const unsigned int /*ver*/)
      {
        a & m_keys;
        a & m_creation_timestamp;
      }


    BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(m_keys)
        KV_SERIALIZE(m_creation_timestamp)
      END_KV_SERIALIZE_MAP()

    private:
      void set_null();

      std::string username;
      safex_account_keys m_keys;
      uint64_t m_creation_timestamp;
  };

  struct safex_account
  {
    public:
      safex_account(): username{}, pkey{}, account_data{} {
        CHECK_AND_ASSERT_MES_NO_RET(account_data.size() < MAX_ACCOUNT_DATA_SIZE, "Safex account data size limited to " << MAX_ACCOUNT_DATA_SIZE);
      }

      safex_account(const std::string _username, const crypto::public_key _pkey, const std::vector<uint8_t> &_account_data) :
      username{_username}, pkey{_pkey}, account_data{_account_data}
      {

      }

    BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(username)
        KV_SERIALIZE(pkey)
        KV_SERIALIZE(account_data)
      END_KV_SERIALIZE_MAP()

      BEGIN_SERIALIZE_OBJECT()
        FIELD(username)
        FIELD(pkey)
        FIELD(account_data)
      END_SERIALIZE()


      std::string username;
      crypto::public_key pkey;
      std::vector<uint8_t> account_data;
  };
}


#endif //SAFEX_SAFEX_ACCOUNT_H
