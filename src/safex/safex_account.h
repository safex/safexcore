//
// Created by amarko on 22.7.19..
//

#ifndef SAFEX_SAFEX_ACCOUNT_H
#define SAFEX_SAFEX_ACCOUNT_H


#include <string>
#include <cryptonote_basic/cryptonote_basic.h>

#include "device/device.hpp"
#include "crypto/crypto.h"
#include "serialization/keyvalue_serialization.h"

#include "safex_core.h"

#undef SAFEX_DEFAULT_LOG_CATEGORY
#define SAFEX_DEFAULT_LOG_CATEGORY "safex_account"

namespace safex
{

  const int MAX_ACCOUNT_DATA_SIZE = 1024;


  bool parse_safex_account_key(const cryptonote::txout_target_v &txout, crypto::public_key& pkey);

  bool check_safex_account_signature(const crypto::hash &tx_prefix_hash, const crypto::public_key &sender_safex_account_key, const crypto::signature &signature);


  struct safex_account_keys
  {


    safex_account_keys &operator=(const safex_account_keys &) = default;

    hw::device &get_device() const;

    bool valid() const
    {
      return ((m_secret_key != crypto::secret_key{}) && (m_public_key != crypto::public_key{}) && crypto::check_key(m_public_key));
    }

    template <typename t_archive>
    inline void serialize(t_archive &a, const unsigned int ver)
    {
      a & m_public_key;
      a & m_secret_key;
    }

    void set_device(hw::device &hwdev);

    crypto::public_key m_public_key;
    crypto::secret_key m_secret_key;
    hw::device *m_device = &hw::get_device("default");

    crypto::public_key get_public_key() const {
      return m_public_key;
    }

    crypto::secret_key get_secret_key() const {
      return m_secret_key;
    }

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(m_public_key)
      KV_SERIALIZE(m_secret_key)
    END_KV_SERIALIZE_MAP()


  };

  class safex_account_key_handler
  {
    public:
      safex_account_key_handler() {}

      crypto::secret_key generate(const crypto::secret_key &recovery_key = crypto::secret_key(), bool recover = false);

      void create_from_device(const std::string &device_name);

      void create_from_keys(const crypto::secret_key &privatekey);

      const safex_account_keys &get_keys() const {
        return m_keys;
      };

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

      bool valid() const {
        return (!(username.empty()));
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

      template<class t_archive>
      inline void serialize(t_archive &a, const unsigned int /*ver*/)
      {
        a & username;
        a & pkey;
        a & account_data;
      }


      std::string username;
      crypto::public_key pkey;
      std::vector<uint8_t> account_data;
  };
}


#endif //SAFEX_SAFEX_ACCOUNT_H
