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


char* returnStdString(std::string& in) {
	char* dst = (char*) malloc(in.size()* sizeof(char));
	memcpy(dst, tx.c_str(), in.size());
	return dst;
}

extern "C" void* win_createWallet(uint8_t nettype) {

	printf("Called %s \n", __FUNCTION__);
	Safex::WalletImpl* wallet = new Safex::WalletImpl(static_cast<Safex::NetworkType>(nettype));
	return static_cast<void*>(wallet);
}

extern "C" uint8_t win_initB(void* self, char* daemon_address){
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	return static_cast<uint8_t>(wallet->init(daemon_address));
}

extern "C" void win_startRefresh(void* self){
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	wallet->startRefresh();
}

extern "C" uint8_t win_storeB(void* self, char* path){
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	return static_cast<bool>(wallet->store(path));
}

extern "C" void* win_createTransaction(
		void* self,
		char* dst_addr,
		char* payment_id,
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

extern "C" char* win_address(void* self) {
    Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	printf("Called %s \n", __FUNCTION__);

	return returnStdString(wallet->address());

}
extern "C" char* win_seed(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return returnStdString(wallet->seed());
}
extern "C" char* win_path(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return returnStdString(wallet->path());
}
extern "C" uint8_t win_nettype(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return static_cast<uint8_t>(wallet->nettype());
}
extern "C" char* win_secretViewKey(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return returnStdString(wallet->secretViewKey());
}
extern "C" char* win_publicViewKey(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return returnStdString(wallet->publicViewKey());
}
extern "C" char* win_secretSpendKey(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return returnStdString(wallet->secretSpendKey());
}
extern "C" char* win_publicSpendKey(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return returnStdString(wallet->publicSpendKey());
}
extern "C" uint8_t win_setPasswordB(void* self, char* pass_c) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	std::string password(pass_c);
	
	return static_cast<uint8_t>(wallet->setPassword(password));
}
extern "C" char* win_errorString(void* self) {
    Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
    
    return returnStdString(wallet->errorString());
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

extern "C" char* win_pt_errorString(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return returnStdString(ptx->errorString());
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
extern "C" void* win_mng_createWallet(void* self, char* path, char* password, char* lang, uint32_t nettype) {
	Safex::WalletManagerImpl* mngr = static_cast<Safex::WalletManagerImpl*>(self);
	printf("Hello from %s \n", __FUNCTION__);
	return static_cast<void*>(mngr->createWallet(path, password, lang, static_cast<Safex::NetworkType>(nettype)));
}

// @return Safex::WalletImpl
extern "C" void* win_mng_openWallet(void* self, char* path, char* password, uint32_t nettype) {
	Safex::WalletManagerImpl* mngr = static_cast<Safex::WalletManagerImpl*>(self);
	printf("Hello from %s \n", __FUNCTION__);
	return static_cast<void*>(mngr->openWallet(path, password, static_cast<Safex::NetworkType>(nettype)));
}

// @return Safex::WalletImpl
extern "C" void* win_mng_recoveryWallet(
		void* self,
		char* path,
		char* password,
		char* mnemonic,
		uint32_t nettype,
		uint64_t restoreHeight) {
	Safex::WalletManagerImpl* mngr = static_cast<Safex::WalletManagerImpl*>(self);
	printf("Hello from %s \n", __FUNCTION__);
	return static_cast<void*>(mngr->recoveryWallet(path, password, mnemonic, static_cast<Safex::NetworkType>(nettype), restoreHeight));
}

extern "C" uint8_t win_mng_walletExists(void* self, char* path) {
	Safex::WalletManagerImpl* mngr = static_cast<Safex::WalletManagerImpl*>(self);
	printf("Hello from %s \n", __FUNCTION__);
	return static_cast<uint8_t>(mngr->walletExists(path));
}

extern "C" void* win_mngf_getWalletManager() {
	Safex::WalletManager* mngr = Safex::WalletManagerFactory::getWalletManager();
	return static_cast<void*>(mngr);
}
/****************************** END WALLET MANAGER API ****************************************************************/
/****************************** TRANSACTIONINFO API *******************************************************************/
extern "C" void* win_txinfo_createTransactionInfo() {

}
extern "C" int32_t win_txinfo_direction(void* self) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	return static_cast<int32_t>(txInfo->direction());
}

extern "C" uint8_t win_txinfo_isPendingB(void* self) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	return static_cast<uint8_t>(txInfo->isPending());
}

extern "C" uint8_t win_txinfo_isFailedB(void* self) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	return static_cast<uint8_t>(txInfo->isFailed());
}

extern "C" uint64_t win_txinfo_amount(void* self) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	return txInfo->amount();
}

extern "C" uint64_t win_txinfo_fee(void* self) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	return txInfo->fee();
}

extern "C" uint64_t win_txinfo_blockHeight(void* self) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	return txInfo->blockHeight();
}

extern "C" const char* win_txinfo_label(void* self) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	return  returnStdString(txInfo->label());
}

extern "C" const char* win_txinfo_hash(void* self) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	return  returnStdString(txInfo->hash());
}

extern "C" uint64_t win_txinfo_timestamp(void* self) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	return static_cast<uint64_t>(txInfo->timestamp());
}

extern "C" const_char* win_txinfo_paymentId(void* self) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	return  returnStdString(txInfo->paymentId());
}

extern "C" void* win_txinfo_transfers(void* self, uint32_t size) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	const std::vector<Safex::Transfer>& transfers = txIndo->transfers();
	size = transfers.size();
	return static_cast<void*>(transfers.data());
}

extern "C" uint64_t win_txinfo_confirmations(void* self) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	return txInfo->confirmations();
}

extern "C" uint64_t win_txinfo_unlockTime(void* self) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	return static_cast<uint64_t>(txInfo->unlockTime());
}

extern "C" uint32_t win_txinfo_transactionType(void* self) {
	Safex::TransactionInfo* txInfo = static_cast<Safex::TransactionInfo*>(self);
	return static_cast<uint32_t>(txInfo->transactionType());
}

/****************************** END TRANSACTIONINFO API ***************************************************************/