//
// Created by stefan on 28.11.18..
//

/*
 * In order to link wallet library on windows and get portability C API needs to be create
 * to avoid name mangling during linkage.
 */

#ifndef SAFEX_WINDOWS_WRAPPER_H
#define SAFEX_WINDOWS_WRAPPER_H

#include "../wallet_api.h"
#include "../wallet.h"

extern "C" void* win_createWallet(uint8_t nettype);
extern "C" const char* win_address(void* self);
extern "C" const char* win_seed(void* self);
extern "C" const char* win_path(void* self);
extern "C" uint8_t win_nettype(void* self);
extern "C" const char* win_secretViewKey(void* self);
extern "C" const char* win_publicViewKey(void* self);
extern "C" const char* win_secretSpendKey(void* self);
extern "C" const char* win_publicSpendKey(void* self);
extern "C" uint8_t win_setPasswordB(void* self, const char*); // @todo See if bool is valid in CAPI
extern "C" const char* win_errorString(void* self);
extern "C" void win_setRefreshFromBlockeHeight(void* self, uint32_t height);
extern "C" uint32_t win_connected(void* self); // @todo Enum ConnectionStatus without default type should be uint32_t
extern "C" void win_setTrustedDaemon(void* self, uint8_t argB);
extern "C" uint8_t win_trustedDaemonB(void* self);
extern "C" uint64_t win_balanceAll(void* self);
extern "C" uint64_t win_unlockedBallanceAll(void* self);
extern "C" uint64_t win_tokenBalanceAll(void* self);
extern "C" uint64_t win_unlockedTokenBallanceAll(void* self);


#endif //SAFEX_WINDOWS_WRAPPER_H
