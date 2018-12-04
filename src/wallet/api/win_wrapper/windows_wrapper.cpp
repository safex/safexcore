//
// Created by stefan on 28.11.18..
//

#include <vector>
#include <string>
#include <iostream>

#include <cstdlib>
#include <cstring>
#include <stdio.h>

#include "windows_wrapper.h"
#include "../wallet.h"
#include "../pending_transaction.h"
#include "../transaction_info.h"
#include "../wallet_manager.h"
#include "../wallet_api.h"
#include "windows_wallet_listener.h"


char* returnStdString(std::string&& in) {
	char* dst = (char*) malloc(in.size()* sizeof(char));
	memcpy(dst, in.c_str(), in.size());
	return dst;
}

extern "C" DLL_MAGIC  void win_checkDLL(const char* msg) {
	printf("Message from below: %s \n", msg);
	std::cout << "message bab ba std::cout " << std::endl;
	fflush (stdout);
	
}

extern "C" DLL_MAGIC  void* win_createWallet(uint8_t nettype) {

	printf("Called %s \n", __FUNCTION__);
	Safex::WalletImpl* wallet = new Safex::WalletImpl(static_cast<Safex::NetworkType>(nettype));
	return static_cast<void*>(wallet);
}

extern "C" DLL_MAGIC  void win_deleteWallet(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	if(wallet) {
		delete wallet;
	}
}

extern "C" DLL_MAGIC  uint8_t win_initB(void* self, const char* daemon_address){
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	return static_cast<uint8_t>(wallet->init(daemon_address));
}

extern "C" DLL_MAGIC  void win_startRefresh(void* self){
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	wallet->startRefresh();
}

extern "C" DLL_MAGIC  uint8_t win_storeB(void* self, const char* path){
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	return static_cast<bool>(wallet->store(path));
}

extern "C" DLL_MAGIC  void* win_createTransaction(
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

extern "C" DLL_MAGIC const char*win_address(void* self) {
    Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	printf("Called %s \n", __FUNCTION__);

	return wallet->address().c_str();

}
extern "C" DLL_MAGIC const char*win_seed(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return wallet->seed().c_str();
}
extern "C" DLL_MAGIC const char*win_path(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return wallet->path().c_str();
}
extern "C" DLL_MAGIC  uint8_t win_nettype(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return static_cast<uint8_t>(wallet->nettype());
}
extern "C" DLL_MAGIC const char*win_secretViewKey(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return wallet->secretViewKey().c_str();
}
extern "C" DLL_MAGIC const char*win_publicViewKey(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return wallet->publicViewKey().c_str();
}
extern "C" DLL_MAGIC const char*win_secretSpendKey(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return wallet->secretSpendKey().c_str();
}
extern "C" DLL_MAGIC const char*win_publicSpendKey(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);

	return wallet->publicSpendKey().c_str();
}
extern "C" DLL_MAGIC  uint8_t win_setPasswordB(void* self, const char* pass_c) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	std::string password(pass_c);
	
	return static_cast<uint8_t>(wallet->setPassword(password));
}
extern "C" DLL_MAGIC const char*win_errorString(void* self) {
    Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
    
    return wallet->errorString().c_str();
}
extern "C" DLL_MAGIC  void win_setRefreshFromBlockHeight(void* self, uint32_t height) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	wallet->setRefreshFromBlockHeight(height);
}
extern "C" DLL_MAGIC  uint32_t win_connected(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return static_cast<uint32_t>(wallet->connected());
}
extern "C" DLL_MAGIC  void win_setTrustedDaemon(void* self, uint8_t argB) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	bool arg = (argB == 0);
	wallet->setTrustedDaemon(arg);
}
extern "C" DLL_MAGIC  uint8_t win_trustedDaemonB(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return static_cast<uint8_t>(wallet->trustedDaemon());
}
extern "C" DLL_MAGIC  uint64_t win_balanceAll(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return wallet->balanceAll();
}
extern "C" DLL_MAGIC  uint64_t win_unlockedBalanceAll(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return wallet->unlockedBalanceAll();
}
extern "C" DLL_MAGIC  uint64_t win_tokenBalanceAll(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return wallet->tokenBalanceAll();
}
extern "C" DLL_MAGIC  uint64_t win_unlockedTokenBalanceAll(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	
	return wallet->unlockedTokenBalanceAll();
}

extern "C" DLL_MAGIC  uint8_t win_static_addressValid(const char* address, uint32_t nettype) {
	return static_cast<uint8_t>(Safex::Wallet::addressValid(address, static_cast<Safex::NetworkType>(nettype)));
}

extern "C" DLL_MAGIC const char*win_GenPaymentId() {
	return Safex::Wallet::genPaymentId().c_str();
}

extern "C" DLL_MAGIC  uint8_t win_PaymentIdValid( const char* pid) {
	return static_cast<uint8_t>(Safex::Wallet::paymentIdValid(pid));
}

extern "C" DLL_MAGIC  void win_SetListener(void* self, void* listener) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(listener);
	wallet->setListener(wlstn);
}

extern "C" DLL_MAGIC  void win_segregatePreForkOutputs(void* self, uint8_t segregateB) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	wallet->segregatePreForkOutputs(static_cast<bool>(segregateB));
}

extern "C" DLL_MAGIC  void win_keyReuseMitigation2(void* self, uint8_t mitigationB) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	wallet->keyReuseMitigation2(static_cast<bool>(mitigationB));
}

extern "C" DLL_MAGIC const char*win_IntegratedAddress(void* self, const char* paymentId) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	return wallet->integratedAddress(paymentId).c_str();
}


/****************************** PENDING TRANSACTION API ***************************************************************/
extern "C" DLL_MAGIC  void* win_pt_create(void* in) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(in);
	Safex::PendingTransactionImpl* ret = new Safex::PendingTransactionImpl(*wallet);
	return static_cast<void*>(ret);
}

extern "C" DLL_MAGIC  void win_pt_delete(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	if(ptx) {
		delete ptx;
	}
}

extern "C" DLL_MAGIC  uint64_t win_pt_amount(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->amount();
}

extern "C" DLL_MAGIC  uint64_t win_pt_tokenAmount(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->tokenAmount();
}

extern "C" DLL_MAGIC  uint64_t win_pt_dust(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->dust();
}

extern "C" DLL_MAGIC  uint64_t win_pt_fee(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->fee();
}

extern "C" DLL_MAGIC  uint64_t win_pt_txCount(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->txCount();
}

extern "C" DLL_MAGIC  char** win_pt_txid(void* self) {
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

extern "C" DLL_MAGIC  int32_t win_pt_status(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->status();
}

extern "C" DLL_MAGIC const char*win_pt_errorString(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return ptx->errorString().c_str();
}

extern "C" DLL_MAGIC  uint8_t win_pt_commit(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	printf("Hello from %s \n", __FUNCTION__);

	return static_cast<uint8_t>(ptx->commit());
}
/****************************** END PENDING TRANSACTION API ***********************************************************/


/****************************** WALLET MANAGER API ********************************************************************/
extern "C" DLL_MAGIC  void win_mng_closeWallet(void* self, void* wallet, uint8_t storeB) {
	Safex::WalletManagerImpl* mngr = static_cast<Safex::WalletManagerImpl*>(self);
	Safex::WalletImpl* wllt = static_cast<Safex::WalletImpl*>(wallet);
	mngr->closeWallet(wllt, static_cast<bool>(storeB));
	printf("Hello from %s \n", __FUNCTION__);
}

// @return Safex::WalletImpl
extern "C" DLL_MAGIC  void* win_mng_createWallet(void* self, const char* path,const  char* password, const char* lang, uint32_t nettype) {
	Safex::WalletManagerImpl* mngr = static_cast<Safex::WalletManagerImpl*>(self);
	printf("Hello from %s \n", __FUNCTION__);
	return static_cast<void*>(mngr->createWallet(path, password, lang, static_cast<Safex::NetworkType>(nettype)));
}

// @return Safex::WalletImpl
extern "C" DLL_MAGIC  void* win_mng_openWallet(void* self, const char* path, const char* password, uint32_t nettype) {
	Safex::WalletManagerImpl* mngr = static_cast<Safex::WalletManagerImpl*>(self);
	printf("Hello from %s \n", __FUNCTION__);
	return static_cast<void*>(mngr->openWallet(path, password, static_cast<Safex::NetworkType>(nettype)));
}

// @return Safex::WalletImpl
extern "C" DLL_MAGIC  void* win_mng_recoveryWallet(
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

extern "C" DLL_MAGIC  uint8_t win_mng_walletExists(void* self, const char* path) {
	Safex::WalletManagerImpl* mngr = static_cast<Safex::WalletManagerImpl*>(self);
	printf("Hello from %s \n", __FUNCTION__);
	return static_cast<uint8_t>(mngr->walletExists(path));
}

extern "C" DLL_MAGIC  void* win_mngf_getWalletManager() {
	Safex::WalletManager* mngr = Safex::WalletManagerFactory::getWalletManager();
	return static_cast<void*>(mngr);
}
/****************************** END WALLET MANAGER API ****************************************************************/
/****************************** TRANSACTIONINFO API *******************************************************************/
extern "C" DLL_MAGIC  void* win_txinfo_createTransactionInfo() {
	Safex::TransactionInfoImpl* txInfo = new Safex::TransactionInfoImpl();
	return static_cast<void*>(txInfo);
}

extern "C" DLL_MAGIC  void win_txinfo_deleteTransactionInfo(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	if(txInfo) {
		delete txInfo;
	}
}

extern "C" DLL_MAGIC  int32_t win_txinfo_direction(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return static_cast<int32_t>(txInfo->direction());
}

extern "C" DLL_MAGIC  uint8_t win_txinfo_isPendingB(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return static_cast<uint8_t>(txInfo->isPending());
}

extern "C" DLL_MAGIC  uint8_t win_txinfo_isFailedB(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return static_cast<uint8_t>(txInfo->isFailed());
}

extern "C" DLL_MAGIC  uint64_t win_txinfo_amount(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return txInfo->amount();
}

extern "C" DLL_MAGIC  uint64_t win_txinfo_fee(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return txInfo->fee();
}

extern "C" DLL_MAGIC  uint64_t win_txinfo_blockHeight(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return txInfo->blockHeight();
}

extern "C" DLL_MAGIC const char*win_txinfo_label(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return  txInfo->label().c_str();
}

extern "C" DLL_MAGIC const char*win_txinfo_hash(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return  txInfo->hash().c_str();
}

extern "C" DLL_MAGIC  uint64_t win_txinfo_timestamp(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return static_cast<uint64_t>(txInfo->timestamp());
}

extern "C" DLL_MAGIC const char*win_txinfo_paymentId(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return  txInfo->paymentId().c_str();
}

extern "C" DLL_MAGIC  void* win_txinfo_transfers(void* self, uint32_t* size) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	const std::vector<Safex::TransactionInfo::Transfer>& transfers = txInfo->transfers();
	*size = transfers.size();
	return static_cast<void*>(const_cast<Safex::TransactionInfo::Transfer*>(transfers.data()));
}

extern "C" DLL_MAGIC  uint64_t win_txinfo_confirmations(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return txInfo->confirmations();
}

extern "C" DLL_MAGIC  uint64_t win_txinfo_unlockTime(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return static_cast<uint64_t>(txInfo->unlockTime());
}

extern "C" DLL_MAGIC  uint32_t win_txinfo_transactionType(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return static_cast<uint32_t>(txInfo->transactionType());
}

/****************************** END TRANSACTIONINFO API ***************************************************************/

/****************************** WALLET LISTENER API ********************************************************************/
extern "C" DLL_MAGIC  void* win_lstn_Create(void* up) {
	return static_cast<void*>(new WinWalletListener(up));
}
extern "C" DLL_MAGIC void win_lstn_setMoneySpent(void* self, void(*moneySpent_)(void*,const char*, uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->moneySpent_ = moneySpent_;
}
extern "C" DLL_MAGIC void win_lstn_setMoneyReceived(void* self, void(*moneyReceived_)(void*,const char*, uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->moneyReceived_ = moneyReceived_;
}

extern "C" DLL_MAGIC void win_lstn_setUnconfirmedMoneyReceived(void* self, void(*unconfirmedMoneyReceived_)(void*,const char*, uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->unconfirmedMoneyReceived_ = unconfirmedMoneyReceived_;
}
extern "C" DLL_MAGIC void win_lstn_setTokensSpent(void* self, void(*tokensSpent_)(void*,const char*, uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->tokensSpent_ = tokensSpent_;
}

extern "C" DLL_MAGIC void win_lstn_setTokenReceived(void* self, void(*tokenReceived_)(void*,const char*, uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->tokenReceived_ = tokenReceived_;
}

extern "C" DLL_MAGIC void win_lstn_setUnconfirmedTokenReceived(void* self, void(*unconfirmedTokenReceived_)(void*,const char*, uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->unconfirmedTokenReceived_ = unconfirmedTokenReceived_;
}

extern "C" DLL_MAGIC void win_lstn_setNewBlock(void* self, void(*newBlock_)(void*,uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->newBlock_ = newBlock_;
}

extern "C" DLL_MAGIC void win_lstn_setUpdated(void* self, void(*updated_)(void*)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->updated_ = updated_;
}
extern "C" DLL_MAGIC void win_lstn_setRefreshed(void* self, void(*refreshed_)(void*)){
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->refreshed_ = refreshed_;
}

/****************************** END WALLET LISTNER API ****************************************************************/