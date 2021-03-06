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


set(safex_core_sources
        command.cpp
        fee_distribution.cpp
        safex_core.cpp
        safex_account.cpp
        safex_offer.cpp
        safex_purchase.cpp
        safex_feedback_token.cpp
        safex_feedback.cpp
        safex_price_peg.cpp
        )

set(safex_core_headers
        command.h
        fee_distribution.h
        safex_account.h
        safex_offer.h
        safex_purchase.h
        safex_feedback_token.h
        safex_feedback.h
        safex_price_peg.h
        )

set(safex_core_private_headers)

safex_private_headers(safex_core
        ${safex_core_private_headers})

safex_add_library(safex_core
        ${safex_core_sources}
        ${safex_core_headers}
        ${safex_core_private_headers})

target_link_libraries(safex_core
        PUBLIC
        cncrypto
        common
        PRIVATE
        ${EXTRA_LIBRARIES})
