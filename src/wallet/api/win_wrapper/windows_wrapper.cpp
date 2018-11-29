//
// Created by stefan on 28.11.18..
//

#include <vector>
#include <string>

#include <cstdlib>
#include <cstring>

#include "windows_wrapper.h"
#include "../wallet.h"
#include "../pending_transaction.h"
#include "../wallet_manager.h"
#include "../wallet_api.h"


extern "C" void* win_createWallet(uint8_t nettype) {

	printf("Called %s \n", __FUNCTION__);
	Safex::WalletImpl* wallet = new Safex::WalletImpl(static_cast<Safex::NetworkType>(nettype));
	return static_cast<void*>(wallet);
}

extern "C" uint8_t win_initB(void* self, const char* daemon_address){
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	return static_cast<uint8_t>(wallet->init(daemon_address));
}

extern "C" void win_startRefresh(void* self){
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	wallet->startRefresh();
}

extern "C" uint8_t win_storeB(void* self, const char* path){
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	return static_cast<bool>(wallet->store(path));
}

extern "C" void* win_createTransaction(
		void* self,
		const char* dst_addr,
		const char* payment_id,
		uint64_t value_amount,
		uint32_t mixin_count,
		uint32_t priority,
		uint32_t subaddr_account,
		uint32_t subaddr_indices,
		uint32_t tx_type) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	Safex::PendingTransaction* pTx = wallet->createTransaction(
			dst_addr,
			payment_id,
			value_amount,
			mixin_count,
			static_cast<Safex::PendingTransaction::Priority>(priority),
			0,
			{},
			static_cast<Safex::TransactionType>(tx_type)
	);

	return static_cast<void*>(pTx);
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
extern "C" void win_setRefreshFromBlockHeight(void* self, uint32_t height) {
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
extern "C" uint64_t win_unlockedBalanceAll(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return wallet->unlockedBalanceAll();
}
extern "C" uint64_t win_tokenBalanceAll(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return wallet->tokenBalanceAll();
}
extern "C" uint64_t win_unlockedTokenBalanceAll(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return wallet->unlockedTokenBalanceAll();
}

/****************************** PENDING TRANSACTION API ***************************************************************/
extern "C" uint64_t win_pt_amount(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->amount();
}

extern "C" uint64_t win_pt_tokenAmount(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->tokenAmount();
}

extern "C" uint64_t win_pt_dust(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->dust();
}

extern "C" uint64_t win_pt_fee(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->fee();
}

extern "C" uint64_t win_pt_txCount(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->txCount();
}

extern "C" char** win_pt_txid(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	std::vector<std::string> ret = ptx->txid();

	char** retVal;
	retVal = new char*[ret.size()+1];
	size_t i = 0;
	for(auto& tx : ret) {
		uint32_t len = tx.size();
		char* dst = (char*) malloc(len * sizeof(char));
		retVal[i++] = dst;
		memcpy(dst, tx.c_str(), len);
	}
	retVal[i] = nullptr;
	return retVal;
}

extern "C" int32_t win_pt_status(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->status();
}

extern "C" const char* win_pt_errorString(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->errorString().c_str();
}

extern "C" uint8_t win_pt_commit(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return static_cast<uint8_t>(ptx->commit());
}
/****************************** END PENDING TRANSACTION API ***********************************************************/


/****************************** WALLET MANAGER API ********************************************************************/
extern "C" void win_mng_closeWallet(void* self, void* wallet, uint8_t storeB) {
	Safex::WalletManagerImpl* mngr = static_cast<Safex::WalletManagerImpl*>(self);
	Safex::WalletImpl* wllt = static_cast<Safex::WalletImpl*>(wallet);
	mngr->closeWallet(wllt, static_cast<bool>(storeB));
	printf("Hello from %s \n", __FUNCTION__);
}

// @return Safex::WalletImpl
extern "C" void* win_mng_createWallet(void* self, const char* path, const char* password, const char* lang, uint32_t nettype) {
	Safex::WalletManagerImpl* mngr = static_cast<Safex::WalletManagerImpl*>(self);
	printf("Hello from %s \n", __FUNCTION__);
	return static_cast<void*>(mngr->createWallet(path, password, lang, static_cast<Safex::NetworkType>(nettype)));
}

// @return Safex::WalletImpl
extern "C" void* win_mng_openWallet(void* self, const char* path, const char* password, uint32_t nettype) {
	Safex::WalletManagerImpl* mngr = static_cast<Safex::WalletManagerImpl*>(self);
	printf("Hello from %s \n", __FUNCTION__);
	return static_cast<void*>(mngr->openWallet(path, password, static_cast<Safex::NetworkType>(nettype)));
}

// @return Safex::WalletImpl
extern "C" void* win_mng_recoveryWallet(
		void* self,
		const char* path,
		const char* password,
		const char* mnemonic,
		uint32_t nettype,
		uint64_t restoreHeight) {
	Safex::WalletManagerImpl* mngr = static_cast<Safex::WalletManagerImpl*>(self);
	printf("Hello from %s \n", __FUNCTION__);
	return static_cast<void*>(mngr->recoveryWallet(path, password, mnemonic, static_cast<Safex::NetworkType>(nettype), restoreHeight));
}

extern "C" uint8_t win_mng_walletExists(void* self, const char* path) {
	Safex::WalletManagerImpl* mngr = static_cast<Safex::WalletManagerImpl*>(self);
	printf("Hello from %s \n", __FUNCTION__);
	return static_cast<uint8_t>(mngr->walletExists(path));
}

extern "C" void* win_mngf_getWalletManager() {
	Safex::WalletManager* mngr = Safex::WalletManagerFactory::getWalletManager();
	return static_cast<void*>(mngr);
}
/****************************** END WALLET MANAGER API ****************************************************************/