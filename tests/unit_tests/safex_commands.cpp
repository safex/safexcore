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
// Parts of this file are originally copyright (c) 2017-2018 The Monero Project

#include "gtest/gtest.h"
#include "safex/command.h"
#include <vector>
#include <iostream>

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/hardfork.h"
#include "safex_test_common.h"


using namespace safex;

TEST(SafexCommandParsing, HandlesTokenLock)
{

  token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION, 2000};

  //serialize
  std::vector<uint8_t> serialized_command;
  safex_command_serializer::serialize_safex_object(command1, serialized_command);



  command_t command_type = safex_command_serializer::get_command_type(serialized_command);
  ASSERT_EQ(command_type, command_t::token_stake) << "Token stake command type not properly parsed from binary blob";

  //deserialize
  std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(serialized_command, command_t::token_stake);

  ASSERT_EQ(command1.get_version(), command2->get_version()) << "Original and deserialized command must have same version";
  ASSERT_EQ(command1.get_command_type(), command2->get_command_type()) << "Original and deserialized command must have same command type";
  ASSERT_EQ(command1.get_staked_token_amount(), dynamic_cast<safex::token_stake*>(command2.get())->get_staked_token_amount()) << "Original and deserialized command must have same locked amount";

}

TEST(SafexCommandParsing, HandlesTokenCollect)
{

  token_collect command1{SAFEX_COMMAND_PROTOCOL_VERSION, 2000};

  //serialize
  std::vector<uint8_t> serialized_command;
  safex_command_serializer::serialize_safex_object(command1, serialized_command);

  command_t command_type = safex_command_serializer::get_command_type(serialized_command);
  ASSERT_EQ(command_type, command_t::token_collect) << "Token unlock command type not properly parsed from binary blob";

  //deserialize
  std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(serialized_command, command_t::token_collect);

  ASSERT_EQ(command1.get_version(), command2->get_version()) << "Original and deserialized command must have same version";
  ASSERT_EQ(command1.get_command_type(), command2->get_command_type()) << "Original and deserialized command must have same command type";
  ASSERT_EQ(command1.get_staked_token_output_index(), dynamic_cast<safex::token_collect*>(command2.get())->get_staked_token_output_index()) << "Original and deserialized command must have same output index";

}

TEST(SafexCommandParsing, HandlesCorruptedArrayOfBytes)
{

  std::vector<uint8_t> serialized_command = {0x32, 0x32, 0x13, 0x43, 0x12, 0x3, 0x4, 0x5, 0x5, 0x6, 0x32, 0x12, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};

  //deserialize
  EXPECT_THROW(safex_command_serializer::parse_safex_object(serialized_command, command_t::token_stake), safex::command_exception);

}


TEST(SafexCommandCreation, HandlesUnknownProtocolVersion)
{

  try
  {
    token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION + 1, 2000};
    FAIL() << "Should throw exception with message invalid command";
  }
  catch (safex::command_exception &exception)
  {
    ASSERT_STREQ(std::string(("Unsupported command protocol version " + std::to_string(SAFEX_COMMAND_PROTOCOL_VERSION + 1))).c_str(), std::string(exception.what()).c_str());
  }
  catch (...)
  {
    FAIL() << "Unexpected exception";
  }
}



namespace
{


  class SafexCommandExecution : public ::testing::Test
  {
    public:
      SafexCommandExecution() {
        crypto::public_key pubKey;
        epee::string_tools::hex_to_pod("229d8c9229ba7aaadcd575cc825ac2bd0301fff46cc05bd01110535ce43a15d1", pubKey);
        keys.push_back(pubKey);

      }
    protected:
      std::vector<crypto::public_key> keys;
      TestDB db;
  };
}

TEST_F(SafexCommandExecution, TokenLockExecute)
{

  try
  {


    cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
    txinput.command_type = command_t::token_stake;
    txinput.token_amount = 10000*SAFEX_TOKEN;
    token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION, 10000*SAFEX_TOKEN};
    safex_command_serializer::serialize_safex_object(command1, txinput.script);

    std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(txinput.script, command_t::token_stake);
    std::unique_ptr<execution_result> result{command2->execute(this->db, txinput)};




    std::cout << "Token amount: " << static_cast<token_stake_result *>(result.get())->token_amount << " status:" << static_cast<int>(result->status)
    << " block number:" << static_cast<token_stake_result*>(result.get())->block_number << std::endl;
  }
  catch (safex::command_exception &exception)
  {
    FAIL() << exception.what();
  }
  catch (std::exception &exception)
  {
    FAIL() << "Exception happened " << exception.what();
  }
  catch (...)
  {
    FAIL() << "Unexpected exception";
  }
}


TEST_F(SafexCommandExecution, TokenLockExceptions)
{

  try
  {

    cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
    txinput.token_amount = 8000;
    txinput.command_type = command_t::token_stake;
    token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION, 8000};
    safex_command_serializer::serialize_safex_object(command1, txinput.script);

    std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(txinput.script, command_t::token_stake);

    std::unique_ptr<execution_result> result{command2->execute(this->db, txinput)};
    FAIL() << "Should throw exception with minimum amount of tokens to lock";

  }
  catch (safex::command_exception &exception)
  {

  }
  catch (std::exception &exception)
  {
    FAIL() << "Exception happened " << exception.what();
  }
  catch (...)
  {
    FAIL() << "Unexpected exception";
  }


  try
  {

    cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
    txinput.token_amount = 19000;
    txinput.command_type = command_t::token_stake;
    token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION, 11000};
    safex_command_serializer::serialize_safex_object(command1, txinput.script);

    std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(txinput.script, command_t::token_stake);

    std::unique_ptr<execution_result> result{command2->execute(this->db, txinput)};
    FAIL() << "Should throw exception with input amount differs from token stake command amount";
  }
  catch (safex::command_exception &exception)
  {

  }
  catch (std::exception &exception)
  {
    FAIL() << "Exception happened " << exception.what();
  }
  catch (...)
  {
    FAIL() << "Unexpected exception";
  }


}


TEST_F(SafexCommandExecution, TokenUnlockExecuteWrongType)
{

  try
  {

    cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
    txinput.token_amount = 10000; //unlock 10k tokens
    txinput.command_type = command_t::token_unstake;
    txinput.key_offsets.push_back(23);
    uint64_t locked_token_output_index = 23;
    token_unstake command1{SAFEX_COMMAND_PROTOCOL_VERSION, locked_token_output_index};
    safex_command_serializer::serialize_safex_object(command1, txinput.script);

    std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(txinput.script, command_t::token_stake);
    std::unique_ptr<execution_result> result{command2->execute(db, txinput)};

  }
  catch (safex::command_exception &exception)
  {
    ASSERT_STREQ("Could not create command, wrong command type", std::string(exception.what()).c_str());

  }
  catch (std::exception &exception)
  {
    FAIL() << "Exception happened " << exception.what();
  }
  catch (...)
  {
    FAIL() << "Unexpected exception";
  }
}


//TEST_F(SafexCommandExecution, TokenUnlockExecute)
//{

//  try
//  {

//    cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
//    txinput.token_amount = 120000; //unlock 120k tokens
//    txinput.command_type = command_t::token_unstake;
//    txinput.key_offsets.push_back(23);
//    uint64_t locked_token_output_index = 23;
//    token_unstake command1{SAFEX_COMMAND_PROTOCOL_VERSION, locked_token_output_index};
//    safex_command_serializer::serialize_safex_object(command1, txinput.script);

//    std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(txinput.script, command_t::token_unstake);
//    std::unique_ptr<execution_result> rslt{command2->execute(this->db, txinput)};
//    token_unstake_result* result = static_cast<token_unstake_result *>(rslt.get());

//    std::cout << "Token amount: " << result->token_amount << " valid:" << result->valid << " block number:" << result->block_number << " interest: " << result->interest << std::endl;
//  }
//  catch (std::exception &exception)
//  {
//    FAIL() << "Exception happened " << exception.what();
//  }
//  catch (...)
//  {
//    FAIL() << "Unexpected exception";
//  }
//}
