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
#include "../transaction_info.h"
#include "../wallet_manager.h"
#include "../wallet_api.h"
#include "windows_wallet_listener.h"


char* returnStdString(std::string&& in) {
	char* dst = (char*) malloc(in.size()* sizeof(char));
	memcpy(dst, in.c_str(), in.size());
	return dst;
}

extern "C" void* win_createWallet(uint8_t nettype) {

	printf("Called %s \n", __FUNCTION__);
	Safex::WalletImpl* wallet = new Safex::WalletImpl(static_cast<Safex::NetworkType>(nettype));
	return static_cast<void*>(wallet);
}

extern "C" void win_deleteWallet(void* self) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	if(wallet) {
		delete wallet;
	}
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
extern "C" uint8_t win_setPasswordB(void* self, const char* pass_c) {
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

extern "C" uint8_t win_static_addressValid(const char* address, uint32_t nettype) {
	return static_cast<uint8_t>(Safex::Wallet::addressValid(address, static_cast<Safex::NetworkType>(nettype)));
}

extern "C" char* win_GenPaymentId() {
	return returnStdString(Safex::Wallet::genPaymentId());
}

extern "C" uint8_t win_PaymentIdValid( const char* pid) {
	return static_cast<uint8_t>(Safex::Wallet::paymentIdValid(pid));
}

extern "C" void win_SetListener(void* self, void* listener) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(listener);
	wallet->setListener(wlstn);
}

extern "C" void win_segregatePreForkOutputs(void* self, uint8_t segregateB) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	wallet->segregatePreForkOutputs(static_cast<bool>(segregateB));
}

extern "C" void win_keyReuseMitigation2(void* self, uint8_t mitigationB) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	wallet->keyReuseMitigation2(static_cast<bool>(mitigationB));
}

extern "C" char* win_IntegratedAddress(void* self, const char* paymentId) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(self);
	return returnStdString(wallet->integratedAddress(paymentId));
}


/****************************** PENDING TRANSACTION API ***************************************************************/
extern "C" void* win_pt_create(void* in) {
	Safex::WalletImpl* wallet = static_cast<Safex::WalletImpl*>(in);
	Safex::PendingTransactionImpl* ret = new Safex::PendingTransactionImpl(*wallet);
	return static_cast<void*>(ret);
}

extern "C" void win_pt_delete(void* self) {
	Safex::PendingTransaction* ptx = static_cast<Safex::PendingTransaction*>(self);
	if(ptx) {
		delete ptx;
	}
}

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
extern "C" void* win_mng_createWallet(void* self, const char* path,const  char* password, const char* lang, uint32_t nettype) {
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
/****************************** TRANSACTIONINFO API *******************************************************************/
extern "C" void* win_txinfo_createTransactionInfo() {
	Safex::TransactionInfoImpl* txInfo = new Safex::TransactionInfoImpl();
	return static_cast<void*>(txInfo);
}

extern "C" void win_txinfo_deleteTransactionInfo(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	if(txInfo) {
		delete txInfo;
	}
}

extern "C" int32_t win_txinfo_direction(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return static_cast<int32_t>(txInfo->direction());
}

extern "C" uint8_t win_txinfo_isPendingB(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return static_cast<uint8_t>(txInfo->isPending());
}

extern "C" uint8_t win_txinfo_isFailedB(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return static_cast<uint8_t>(txInfo->isFailed());
}

extern "C" uint64_t win_txinfo_amount(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return txInfo->amount();
}

extern "C" uint64_t win_txinfo_fee(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return txInfo->fee();
}

extern "C" uint64_t win_txinfo_blockHeight(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return txInfo->blockHeight();
}

extern "C" char* win_txinfo_label(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return  returnStdString(txInfo->label());
}

extern "C" char* win_txinfo_hash(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return  returnStdString(txInfo->hash());
}

extern "C" uint64_t win_txinfo_timestamp(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return static_cast<uint64_t>(txInfo->timestamp());
}

extern "C" char* win_txinfo_paymentId(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return  returnStdString(txInfo->paymentId());
}

extern "C" void* win_txinfo_transfers(void* self, uint32_t* size) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	const std::vector<Safex::TransactionInfo::Transfer>& transfers = txInfo->transfers();
	*size = transfers.size();
	return static_cast<void*>(const_cast<Safex::TransactionInfo::Transfer*>(transfers.data()));
}

extern "C" uint64_t win_txinfo_confirmations(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return txInfo->confirmations();
}

extern "C" uint64_t win_txinfo_unlockTime(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return static_cast<uint64_t>(txInfo->unlockTime());
}

extern "C" uint32_t win_txinfo_transactionType(void* self) {
	Safex::TransactionInfoImpl* txInfo = static_cast<Safex::TransactionInfoImpl*>(self);
	return static_cast<uint32_t>(txInfo->transactionType());
}

/****************************** END TRANSACTIONINFO API ***************************************************************/

/****************************** WALLET LISTENER API ********************************************************************/
extern "C" void* win_lstn_Create() {
	return static_cast<void*>(new WinWalletListener());
}

extern "C" void win_lstn_setMoneySpent(void* self, void(*callback)(const char*, uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->moneySpent_ = callback;
}

extern "C" void win_lstn_setMoneyReceived(void* self, void(*callback)(const char*, uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->moneyReceived_ = callback;
}

extern "C" void win_lstn_setUnconfirmedMoneyReceived(void* self, void(*callback)(const char*, uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->unconfirmedMoneyReceived_ = callback;
}

extern "C" void win_lstn_setTokensSpent(void* self, void(*callback)(const char*, uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->tokensSpent_ = callback;
}

extern "C" void win_lstn_setTokenReceived(void* self, void(*callback)(const char*, uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->tokenReceived_ = callback;
}

extern "C" void win_lstn_setUnconfirmedTokenReceived(void* self, void(*callback)(const char*, uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->unconfirmedTokenReceived_ = callback;
}

extern "C" void win_lstn_setNewBlock(void* self, void(*callback)(uint64_t)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->newBlock_ = callback;
}

extern "C" void win_lstn_setUpdated(void* self, void(*callback)(void)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->updated_ = callback;
}

extern "C" void win_lstn_setRefreshed(void* self, void(*callback)(void)) {
	WinWalletListener* wlstn = static_cast<WinWalletListener*>(self);
	wlstn->refreshed_ = callback;
}

/****************************** END WALLET LISTNER API ****************************************************************/