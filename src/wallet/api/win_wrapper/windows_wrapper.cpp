//
// Created by stefan on 28.11.18..
//

#include "windows_wrapper.h"



extern "C" void* win_createWallet(uint8_t nettype) {
	printf("Called %s \n", __FUNC__);
}
extern "C" const char* win_address(void* self) {
	printf("Called %s \n", __FUNC__);
}
extern "C" const char* win_seed(void* self) {
	printf("Called %s \n", __FUNC__);
}
extern "C" const char* win_path(void* self) {
	printf("Called %s \n", __FUNC__);
}
extern "C" uint8_t win_nettype(void* self) {
	printf("Called %s \n", __FUNC__);
}
extern "C" const char* win_secretViewKey(void* self) {
	printf("Called %s \n", __FUNC__);
}
extern "C" const char* win_publicViewKey(void* self) {
	printf("Called %s \n", __FUNC__);
}
extern "C" const char* win_secretSpendKey(void* self) {
	printf("Called %s \n", __FUNC__);
}
extern "C" const char* win_publicSpendKey(void* self) {
	printf("Called %s \n", __FUNC__);
}
extern "C" uint8_t win_setPasswordB(void* self, const char*) {
	printf("Called %s \n", __FUNC__);
}
extern "C" const char* win_errorString(void* self);
extern "C" void win_setRefreshFromBlockeHeight(void* self, uint32_t height) {
	printf("Called %s \n", __FUNC__);
}
extern "C" uint32_t win_connected(void* self) {
	printf("Called %s \n", __FUNC__);
}
extern "C" void win_setTrustedDaemon(void* self, uint8_t argB) {
	printf("Called %s \n", __FUNC__);
}
extern "C" uint8_t win_trustedDaemonB(void* self) {
	printf("Called %s \n", __FUNC__);
}
extern "C" uint64_t win_balanceAll(void* self) {
	printf("Called %s \n", __FUNC__);
}
extern "C" uint64_t win_unlockedBallanceAll(void* self) {
	printf("Called %s \n", __FUNC__);
}
extern "C" uint64_t win_tokenBalanceAll(void* self) {
	printf("Called %s \n", __FUNC__);
}
extern "C" uint64_t win_unlockedTokenBallanceAll(void* self) {
	printf("Called %s \n", __FUNC__);
}

