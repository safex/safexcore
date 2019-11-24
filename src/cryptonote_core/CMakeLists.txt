# Copyright (c) 2018, The Safex Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Parts of this file are originally copyright (c) 2014-2018 The Monero Project


if(BUILD_SAFEX_PROTOBUF_RPC)    
    FILE(TO_NATIVE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/protobuf/proto PROTOMODEL_PATH)
    FILE(TO_NATIVE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/protobuf PROTOBINDING_PATH)

    FILE(GLOB DATAMODEL_PROTOS "${CMAKE_CURRENT_SOURCE_DIR}/protobuf/proto/*.proto")

    FOREACH(proto ${DATAMODEL_PROTOS})
      FILE(TO_NATIVE_PATH ${proto} proto_native)
      EXECUTE_PROCESS(COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} --proto_path=${PROTOMODEL_PATH} --cpp_out=${PROTOBINDING_PATH} ${proto_native}
      RESULT_VARIABLE rv)
      # Optional, but that can show the user if something have gone wrong with the proto generation 
      IF(${rv})
           MESSAGE("Generation of data model returned ${rv} for proto ${proto_native}")
      ENDIF()
    ENDFOREACH(proto) 

    add_definitions(-DSAFEX_PROTOBUF_RPC=1)
    add_definitions(-DPROTOBUF_INLINE_NOT_IN_HEADERS=0)
    set(cryptonote_core_sources
        blockchain.cpp
        cryptonote_core.cpp
        tx_pool.cpp
        cryptonote_tx_utils.cpp
        protobuf/transactions.pb.cc
        protobuf/output_histogram.pb.cc
        protobuf/blocks.pb.cc
        protobuf/get_outs.pb.cc
        protobuf/cryptonote_to_protobuf.cpp
        )


        set(cryptonote_core_headers)

    set(cryptonote_core_private_headers
      blockchain_storage_boost_serialization.h
      blockchain.h
      protobuf/transactions.pb.h
      protobuf/output_histogram.pb.h
      protobuf/blocks.pb.h
      protobuf/get_outs.pb.h
      protobuf/cryptonote_to_protobuf.h
      cryptonote_core.h
      tx_pool.h
      cryptonote_tx_utils.h)
else()
    set(cryptonote_core_sources
        blockchain.cpp
        cryptonote_core.cpp
        tx_pool.cpp
        cryptonote_tx_utils.cpp
        )

    set(cryptonote_core_headers)

    set(cryptonote_core_private_headers
        blockchain_storage_boost_serialization.h
        blockchain.h
        cryptonote_core.h
        tx_pool.h
        cryptonote_tx_utils.h)
endif()

if(PER_BLOCK_CHECKPOINT)
  set(Blocks "blocks")
else()
  set(Blocks "")
endif()

safex_private_headers(cryptonote_core
  ${cryptonote_core_private_headers})
  
if(BUILD_SAFEX_PROTOBUF_RPC)

  safex_add_library(cryptonote_core
    ${cryptonote_core_sources}
    ${cryptonote_core_headers}
    ${cryptonote_core_private_headers})
  target_link_libraries(cryptonote_core
    PUBLIC
      version
      common
      cncrypto
      blockchain_db
      multisig
      ringct
      device
      ${Boost_DATE_TIME_LIBRARY}
      ${Boost_PROGRAM_OPTIONS_LIBRARY}
      ${Boost_SERIALIZATION_LIBRARY}
      ${Boost_FILESYSTEM_LIBRARY}
      ${Boost_SYSTEM_LIBRARY}
      ${Boost_THREAD_LIBRARY}
      ${PROTOBUF_LIBRARY}
    PRIVATE
      ${Blocks}
      ${EXTRA_LIBRARIES})
else()
     safex_add_library(cryptonote_core
    ${cryptonote_core_sources}
    ${cryptonote_core_headers}
    ${cryptonote_core_private_headers})
  target_link_libraries(cryptonote_core
    PUBLIC
      version
      common
      cncrypto
      blockchain_db
      multisig
      ringct
      device
      ${Boost_DATE_TIME_LIBRARY}
      ${Boost_PROGRAM_OPTIONS_LIBRARY}
      ${Boost_SERIALIZATION_LIBRARY}
      ${Boost_FILESYSTEM_LIBRARY}
      ${Boost_SYSTEM_LIBRARY}
      ${Boost_THREAD_LIBRARY}
    PRIVATE
      ${Blocks}
      ${EXTRA_LIBRARIES}) 
endif()
