// Copyright (c) 2018, The Safex Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
// Parts of this file are originally copyright (c) 2014-2018 The Monero Project

#include "include_base_utils.h"

using namespace epee;

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "include_base_utils.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"

#undef SAFEX_DEFAULT_LOG_CATEGORY
#define SAFEX_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  /**
   * @brief struct for loading a checkpoint from json
   */
  struct t_hashline
  {
    uint64_t height; //!< the height of the checkpoint
    std::string hash; //!< the hash for the checkpoint
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(height)
          KV_SERIALIZE(hash)
        END_KV_SERIALIZE_MAP()
  };

  /**
   * @brief struct for loading many checkpoints from json
   */
  struct t_hash_json {
    std::vector<t_hashline> hashlines; //!< the checkpoint lines from the file
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(hashlines)
        END_KV_SERIALIZE_MAP()
  };

  //---------------------------------------------------------------------------
  checkpoints::checkpoints()
  {
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r = epee::string_tools::parse_tpod_from_hex_string(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    // return false if adding at a height we already have AND the hash is different
    if (m_points.count(height))
    {
      CHECK_AND_ASSERT_MES(h == m_points[height], false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    m_points[height] = h;
    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    return !m_points.empty() && (height <= (--m_points.end())->first);
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool& is_a_checkpoint) const
  {
    auto it = m_points.find(height);
    is_a_checkpoint = it != m_points.end();
    if(!is_a_checkpoint)
      return true;

    if(it->second == h)
    {
      MINFO("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
      return true;
    }else
    {
      MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH: " << it->second << ", FETCHED HASH: " << h);
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h) const
  {
    bool ignored;
    return check_block(height, h, ignored);
  }
  //---------------------------------------------------------------------------
  //FIXME: is this the desired behavior?
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
  {
    if (0 == block_height)
      return false;

    auto it = m_points.upper_bound(blockchain_height);
    // Is blockchain_height before the first checkpoint?
    if (it == m_points.begin())
      return true;

    --it;
    uint64_t checkpoint_height = it->first;
    return checkpoint_height < block_height;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    std::map< uint64_t, crypto::hash >::const_iterator highest = 
        std::max_element( m_points.begin(), m_points.end(),
                         ( boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _1) < 
                           boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _2 ) ) );
    return highest->first;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, crypto::hash>& checkpoints::get_points() const
  {
    return m_points;
  }

  bool checkpoints::check_for_conflicts(const checkpoints& other) const
  {
    for (auto& pt : other.get_points())
    {
      if (m_points.count(pt.first))
      {
        CHECK_AND_ASSERT_MES(pt.second == m_points.at(pt.first), false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
      }
    }
    return true;
  }

  bool checkpoints::init_default_checkpoints(network_type nettype)
  {
    if (nettype == TESTNET)
    {
      ADD_CHECKPOINT(1,     "753e1454ebc44ffb18d7b390f7393a66ce7f3a8aaaf1e4e857af9df4e80d5784");

      return true;
    }

    if (nettype == STAGENET)
    {
      return true;
    }

    ADD_CHECKPOINT(1,     "6b8991102c62bd935da53c64b1357b54a69128d6af63a7a68325b7f613f4b99c");
    ADD_CHECKPOINT(10,    "3b5a5764672afe6b7484d84fe0d715f02b9278654c4feeca5b61203c28d823b3");
    ADD_CHECKPOINT(100,   "fc2ab5b7917156b185ca7b2652bae86ddc853bb2d95c585e3c54862544689d19");
    ADD_CHECKPOINT(1000,  "83ae6093f372081aa353b134b8274b321fd22bc6053ab6f7ce491419490f80c6");
    ADD_CHECKPOINT(10000, "57ee6111ed539f4844f8ed3a2fcc544a5feae7ffee0ea144952e364312a3a8b6");
    ADD_CHECKPOINT(12345, "1570236ccf7048560739959f0411d9fdebf3a45c53ada5f2abd98c88654c540a");
    ADD_CHECKPOINT(15000, "057eeb0ec30fca23465f011482186b69716d483468e661c0ffa570da604673a8");
    ADD_CHECKPOINT(20784, "55072df7488682efc003e191dd5850928f44c1bb575cf6b00fdca0b10e3dba24");
    ADD_CHECKPOINT(29591, "6852b1182d8a9fdbc5a0235736415e2eb3169564ec2679427a7ac374bef23d93");
    ADD_CHECKPOINT(40232, "d4e85e7138b8bfaaa957a3ce2eb9b795b28e00fefc9171728147fb474d19a670");
    ADD_CHECKPOINT(50232, "bc735c8f41122f511dc40ac4a36272606be6f6fddfd7315823d1070fef2a6bc6");
    ADD_CHECKPOINT(66342, "a960ff446a71915cedf0bb9e33524a35d3cf67fd6c2a18d52f6c4bcf859dabc9");
    ADD_CHECKPOINT(70000, "b751e3ef1129815ee03b6deaf75be340cd1bb79bddc8490daace5a510ce3e4c3");
    ADD_CHECKPOINT(79000, "1b17babb026134eedbdd6b2fd3dac889f2dcf16750ae59101fef0f023e60e085");
    ADD_CHECKPOINT(83131, "2dc19db7bd93be7b955b8aa4b17654a0a3c89ee0074f791be28ed90e88127704");
    ADD_CHECKPOINT(87652, "21fb4c908082e4f4b07b52b7a2f6ac783568ff2665b3457906d7b8f7bf210b9e");
    ADD_CHECKPOINT(90200, "bf4e96d3703bfce434bc842e37e2011027617ea083ca80856e430c80146a1b1a");
    ADD_CHECKPOINT(91450, "440675c9a39905dcf04ca2565ad4b7a85961ad68db0baf2e98581bac82241b8d");
    ADD_CHECKPOINT(91999, "f36603a42f4fb29088a53cb7e56232c684b0387f67d911cdd1ddee5335ba57d3");
    ADD_CHECKPOINT(92350, "2af3b3ace2be3e5d9bb28d9cbacf4ed448fc21aadcdb7885a474b61eb72e279e");





    return true;
  }

  bool checkpoints::load_checkpoints_from_json(const std::string &json_hashfile_fullpath)
  {
    boost::system::error_code errcode;
    if (! (boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

    uint64_t prev_max_height = get_max_height();
    LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
    t_hash_json hashes;
    if (!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }
    for (std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end(); )
    {
      uint64_t height;
      height = it->height;
      if (height <= prev_max_height) {
	LOG_PRINT_L1("ignoring checkpoint height " << height);
      } else {
	std::string blockhash = it->hash;
	LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
	ADD_CHECKPOINT(height, blockhash);
      }
      ++it;
    }

    return true;
  }

  bool checkpoints::load_checkpoints_from_dns(network_type nettype)
  {
    std::vector<std::string> records;

    //todo setup safexpulse infrastructure
    static const std::vector<std::string> dns_urls = {
            ""
    };

    static const std::vector<std::string> testnet_dns_urls = {
            ""
    };

    static const std::vector<std::string> stagenet_dns_urls = {
            ""
    };

    if (!tools::dns_utils::load_txt_records_from_dns(records, nettype == TESTNET ? testnet_dns_urls : nettype == STAGENET ? stagenet_dns_urls : dns_urls))
      return true; // why true ?

    for (const auto& record : records)
    {
      auto pos = record.find(":");
      if (pos != std::string::npos)
      {
        uint64_t height;
        crypto::hash hash;

        // parse the first part as uint64_t,
        // if this fails move on to the next record
        std::stringstream ss(record.substr(0, pos));
        if (!(ss >> height))
        {
    continue;
        }

        // parse the second part as crypto::hash,
        // if this fails move on to the next record
        std::string hashStr = record.substr(pos + 1);
        if (!epee::string_tools::parse_tpod_from_hex_string(hashStr, hash))
        {
    continue;
        }

        ADD_CHECKPOINT(height, hashStr);
      }
    }
    return true;
  }

  bool checkpoints::load_new_checkpoints(const std::string &json_hashfile_fullpath, network_type nettype, bool dns)
  {
    bool result;

    result = load_checkpoints_from_json(json_hashfile_fullpath);
    if (dns)
    {
      result &= load_checkpoints_from_dns(nettype);
    }

    return result;
  }
}
