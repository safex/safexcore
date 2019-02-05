//
// Created by stefan on 28.11.18..
//

/*
 * In order to link wallet library on windows and get portability C API needs to be create
 * to avoid name mangling during linkage.
 */

#ifndef SAFEX_WINDOWS_WRAPPER_H
#define SAFEX_WINDOWS_WRAPPER_H

#include <windows.h>

#ifdef DLLIMPORT_SAFEX
#define DLL_MAGIC __declspec(dllimport)
#else
#define DLL_MAGIC __declspec(dllexport)
#endif

/****************************** WALLET API ****************************************************************************/
extern "C" DLL_MAGIC void* win_createWallet(uint8_t nettype);
extern "C" DLL_MAGIC void win_deleteWallet(void* self);
extern "C" DLL_MAGIC void win_checkDLL(const char* msg);

extern "C" DLL_MAGIC uint8_t win_initB(void* self, const char* daemon_address);
extern "C" DLL_MAGIC void win_startRefresh(void* self);
extern "C" DLL_MAGIC uint8_t win_storeB(void* self, const char* path);

// Returning Safex::PendingTransaction
// @warning subaddr_indices is here uint32_t. Argument will be ignored for time being because Safex doesnt support
//          subaddresses. Please be advised to pass integer value instead of initializer_list!!!!!
// Both subaddr fields will be ignored, but are kept here to avoid any serious changes in existing API.
extern "C" DLL_MAGIC void* win_createTransaction(
        void* self,
        const char* dst_addr,
        const char* payment_id,
        uint64_t value_amount,
        uint32_t mixin_count,
        uint32_t priority,
        uint32_t subaddr_account,
        uint32_t subaddr_indices,
        uint32_t tx_type
        );

extern "C" DLL_MAGIC const char* win_address(void* self);
extern "C" DLL_MAGIC const char* win_seed(void* self);
extern "C" DLL_MAGIC const char* win_path(void* self);
extern "C" DLL_MAGIC uint8_t win_nettype(void* self);
extern "C" DLL_MAGIC const char* win_secretViewKey(void* self);
extern "C" DLL_MAGIC const char* win_publicViewKey(void* self);
extern "C" DLL_MAGIC const char* win_secretSpendKey(void* self);
extern "C" DLL_MAGIC const char* win_publicSpendKey(void* self);
extern "C" DLL_MAGIC uint8_t win_setPasswordB(void* self, const char*); // @todo See if bool is valid in CAPI
extern "C" DLL_MAGIC const char* win_errorString(void* self);
extern "C" DLL_MAGIC void win_setRefreshFromBlockHeight(void* self, uint32_t height);
extern "C" DLL_MAGIC uint64_t win_getRefreshFromBlockHeight(void* self);
extern "C" DLL_MAGIC uint32_t win_connected(void* self); // @todo Enum ConnectionStatus without default type should be uint32_t
extern "C" DLL_MAGIC void win_setTrustedDaemon(void* self, uint8_t argB);
extern "C" DLL_MAGIC uint8_t win_trustedDaemonB(void* self);
extern "C" DLL_MAGIC uint64_t win_balanceAll(void* self);
extern "C" DLL_MAGIC uint64_t win_unlockedBalanceAll(void* self);
extern "C" DLL_MAGIC uint64_t win_tokenBalanceAll(void* self);
extern "C" DLL_MAGIC uint64_t win_unlockedTokenBalanceAll(void* self);

extern "C" DLL_MAGIC uint8_t win_synchronizedB(void* self);
extern "C" DLL_MAGIC void win_setAutoRefreshInterval(void* self, uint32_t millis);
extern "C" DLL_MAGIC const char* win_GenPaymentId();
extern "C" DLL_MAGIC uint8_t win_PaymentIdValid(const char* paymentId);
extern "C" DLL_MAGIC void win_SetListener(void* self, void* listener);
extern "C" DLL_MAGIC void win_segregatePreForkOutputs(void* self, uint8_t segregate);
extern "C" DLL_MAGIC void win_keyReuseMitigation2(void* self, uint8_t mitigation);
extern "C" DLL_MAGIC const char* win_IntegratedAddress(void* self, const char* paymentId);
extern "C" DLL_MAGIC uint8_t win_refresh(void* self);


extern "C" DLL_MAGIC uint64_t win_blockChainHeight(void* self);
extern "C" DLL_MAGIC uint64_t win_approximateBlockChainHeight(void* self);
extern "C" DLL_MAGIC uint64_t win_daemonBlockChainHeight(void* self);
extern "C" DLL_MAGIC uint64_t win_daemonBlockChainTargetHeight(void* self);

extern "C" DLL_MAGIC bool win_rescanBlockchain(void* self);
extern "C" DLL_MAGIC void win_rescanBlockchainAsync(void* self);

extern "C" DLL_MAGIC void win_setSeedLanguage(void* self, const char* seedLanguage);

extern "C" DLL_MAGIC uint8_t win_static_addressValid(const char* address, uint32_t nettype);
extern "C" DLL_MAGIC void* win_history(void* self);
/****************************** END WALLET API ************************************************************************/

/****************************** PENDING TRANSACTION API ***************************************************************/
extern "C" DLL_MAGIC void* win_pt_create(void* wallet);
extern "C" DLL_MAGIC void win_pt_delete(void* self);
extern "C" DLL_MAGIC uint64_t win_pt_amount(void* self);
extern "C" DLL_MAGIC uint64_t win_pt_tokenAmount(void* self);
extern "C" DLL_MAGIC uint64_t win_pt_dust(void* self);
extern "C" DLL_MAGIC uint64_t win_pt_fee(void* self);
extern "C" DLL_MAGIC uint64_t win_pt_txCount(void* self);
// @warning Last element is nullptr!! Like
extern "C" DLL_MAGIC char* win_pt_txid(void* self);
extern "C" DLL_MAGIC int32_t win_pt_status(void* self);
extern "C" DLL_MAGIC const char* win_pt_errorString(void* self);
extern "C" DLL_MAGIC uint8_t win_pt_commit(void* self);
/****************************** END PENDING TRANSACTION API ***********************************************************/


/****************************** WALLET MANAGER API ********************************************************************/
extern "C" DLL_MAGIC void* win_mngf_getWalletManager();
extern "C" DLL_MAGIC void win_mng_closeWallet(void* self, void* wallet, uint8_t storeB);
// @return Safex::WalletImpl
extern "C" DLL_MAGIC void* win_mng_createWallet(void* self, const char* path, const char* password, const char* lang, uint32_t nettype);
// @return Safex::WalletImpl
extern "C" DLL_MAGIC void* win_mng_openWallet(void* self, const char* path, const char* password, uint32_t nettype);
// @return Safex::WalletImpl
extern "C" DLL_MAGIC void* win_mng_recoveryWallet(
        void* self,
        const char* path,
        const char* password,
        const char* mnemonic,
        uint32_t nettype,
        uint64_t restoreHeight);
//@return Safex::WalletManager
extern "C" DLL_MAGIC uint8_t win_mng_walletExists(void* self, const char* path);
extern "C" DLL_MAGIC void* win_mng_createWalletFromKeys(void* self, const char* path, const char* password, const char* language, uint32_t nettype,
                                                uint64_t restoreHeight,const char *addressString, const char* viewKeyString, const char* spendKeyString);
/****************************** END WALLET MANAGER API ****************************************************************/

/****************************** TRANSACTIONINFO API *******************************************************************/
extern "C" DLL_MAGIC void* win_txinfo_createTransactionInfo();
extern "C" DLL_MAGIC void win_txinfo_deleteTransactionInfo(void* self);
extern "C" DLL_MAGIC int32_t win_txinfo_direction(void* self);
extern "C" DLL_MAGIC uint8_t win_txinfo_isPendingB(void* self);
extern "C" DLL_MAGIC uint8_t win_txinfo_isFailedB(void* self);
extern "C" DLL_MAGIC uint64_t win_txinfo_amount(void* self);
extern "C" DLL_MAGIC uint64_t win_txinfo_fee(void* self);
extern "C" DLL_MAGIC uint64_t win_txinfo_blockHeight(void* self);
extern "C" DLL_MAGIC const char* win_txinfo_label(void* self);
extern "C" DLL_MAGIC const char* win_txinfo_hash(void* self);
extern "C" DLL_MAGIC uint64_t win_txinfo_timestamp(void* self);
extern "C" DLL_MAGIC const char* win_txinfo_paymentId(void* self);
// returns array of Safex::Transfers
extern "C" DLL_MAGIC char* win_txinfo_transfers(void* self);
extern "C" DLL_MAGIC uint64_t win_txinfo_confirmations(void* self);
extern "C" DLL_MAGIC uint64_t win_txinfo_unlockTime(void* self);
extern "C" DLL_MAGIC uint32_t win_txinfo_transactionType(void* self);
/****************************** END TRANSACTIONINFO API ***************************************************************/

/****************************** WALLET LISTENER API *******************************************************************/
extern "C" DLL_MAGIC void* win_lstn_Create(void*);
extern "C" DLL_MAGIC void win_lstn_setMoneySpent(void* self, void(*moneySpent_)(void*,const char*, uint64_t));
extern "C" DLL_MAGIC void win_lstn_setMoneyReceived(void* self, void(*moneyReceived_)(void*,const char*, uint64_t));
extern "C" DLL_MAGIC void win_lstn_setUnconfirmedMoneyReceived(void* self, void(*unconfirmedMoneyReceived_)(void*,const char*, uint64_t));
extern "C" DLL_MAGIC void win_lstn_setTokensSpent(void* self, void(*tokensSpent_)(void*,const char*, uint64_t));
extern "C" DLL_MAGIC void win_lstn_setTokenReceived(void* self, void(*tokenReceived_)(void*,const char*, uint64_t));
extern "C" DLL_MAGIC void win_lstn_setUnconfirmedTokenReceived(void* self, void(*unconfirmedTokenReceived_)(void*,const char*, uint64_t));
extern "C" DLL_MAGIC void win_lstn_setNewBlock(void* self, void(*newBlock_)(void*,uint64_t));
extern "C" DLL_MAGIC void win_lstn_setUpdated(void* self, void(*updated_)(void*));
extern "C" DLL_MAGIC void win_lstn_setRefreshed(void* self, void(*refreshed_)(void*));
/****************************** END WALLET LISTNER API ****************************************************************/

/****************************** TRANSACTION HISTORY API ***************************************************************/
extern "C" DLL_MAGIC void* win_txhist_Create(void* wallet);
extern "C" DLL_MAGIC void win_txhist_Delete(void* self);
extern "C" DLL_MAGIC uint32_t win_txhist_count(void* self);
extern "C" DLL_MAGIC void* win_txhist_transactionInt(void* self, uint32_t index);
extern "C" DLL_MAGIC void* win_txhist_transactionStr(void* self, const char* id);
extern "C" DLL_MAGIC void** win_txhist_getAll(void* self, uint32_t* size);
extern "C" DLL_MAGIC void win_txhist_refresh(void* self);
/****************************** END TRANSACTION HISTORY API ***********************************************************/

/****************************** OTHER FUNCTIONS ***********************************************************************/
extern "C" DLL_MAGIC void win_mlog_set_log_levelI(int level);
extern "C" DLL_MAGIC void win_mlog_set_log_levelCPtr(const char* log);
/****************************** END OTHER FUNCTIONS *******************************************************************/

#endif //SAFEX_WINDOWS_WRAPPER_H

