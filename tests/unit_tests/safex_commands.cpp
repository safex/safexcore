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

using namespace safex;

TEST(CommandParsing, HandlesTokenLock) {

  token_lock command1{SAFEX_COMMAND_PROTOCOL_VERSION, command_t::token_lock, 2000};

  //serialize
  std::vector<uint8_t> serialized_command;
  safex_command_serializer::store_command(command1, serialized_command);


  command_t command_type = safex_command_serializer::get_command_type(serialized_command);
  ASSERT_EQ(command_type, command_t::token_lock) << "Token lock command type not properly parsed from binary blob";

  //deserialize
  token_lock command2{};
  safex_command_serializer::load_command(serialized_command, command2);

  ASSERT_EQ(command1.version, command2.version) << "Original and deserialized command must have same version";
  ASSERT_EQ(command1.command_type, command2.command_type) << "Original and deserialized command must have same command type";
  ASSERT_EQ(command1.locked_token_amount, command2.locked_token_amount) << "Original and deserialized command must have same locked amount";

}

