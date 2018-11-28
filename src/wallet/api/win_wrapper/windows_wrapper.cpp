//
// Created by stefan on 28.11.18..
//

#include "windows_wrapper.h"
#include "../wallet.h"



extern "C" void* win_createWallet(uint8_t nettype) {

	printf("Called %s \n", __FUNCTION__);
	Safex::WalletImpl* wallet = new Safex::WalleImpl(nettype);
	return static_cast<void*>(wallet);
}
extern "C" const char* win_address(void* self) {
    Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	printf("Called %s \n", __FUNCTION__);

	return wallet->address().c_str();

}
extern "C" const char* win_seed(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return wallet->seed().c_str();
}
extern "C" const char* win_path(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return wallet->path().c_str();
}
extern "C" uint8_t win_nettype(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return static_cast<uint8_t>(wallet->nettype());
}
extern "C" const char* win_secretViewKey(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return wallet->secretViewKey().c_str();
}
extern "C" const char* win_publicViewKey(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return wallet->publicViewKey().c_str();
}
extern "C" const char* win_secretSpendKey(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return wallet->secretSpendKey().c_str();
}
extern "C" const char* win_publicSpendKey(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return wallet->publicSpendKey().c_str();
}
extern "C" uint8_t win_setPasswordB(void* self, const char* pass_c) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	std::string password(pass_c);
	
	return static_cast<uint8_t>(wallet->setPassword(password));
}
extern "C" const char* win_errorString(void* self) {
    Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
    
    return wallet->errorString().c_str();
}
extern "C" void win_setRefreshFromBlockeHeight(void* self, uint32_t height) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	wallet->setRefreshFromBlockHeight(height);
}
extern "C" uint32_t win_connected(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return static_cast<uint32_t>(wallet->connected());
}
extern "C" void win_setTrustedDaemon(void* self, uint8_t argB) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	bool arg = (argB == 0);
	wallet->setTrustedDaemon(arg);
}
extern "C" uint8_t win_trustedDaemonB(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return static_cast<uint8_t>(wallet->trustedDaemon());
}
extern "C" uint64_t win_balanceAll(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return wallet->balanceAll();
}
extern "C" uint64_t win_unlockedBallanceAll(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return wallet->unlockedBalanceAll();
}
extern "C" uint64_t win_tokenBalanceAll(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return wallet->tokenBalanceAll();
}
extern "C" uint64_t win_unlockedTokenBallanceAll(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return wallet->unlockedTokenBalanceAll();
}

