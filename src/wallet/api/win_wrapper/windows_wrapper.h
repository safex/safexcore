//
// Created by stefan on 28.11.18..
//

/*
 * In order to link wallet library on windows and get portability C API needs to be create
 * to avoid name mangling during linkage.
 */

#ifndef SAFEX_WINDOWS_WRAPPER_H
#define SAFEX_WINDOWS_WRAPPER_H


/****************************** WALLET API ****************************************************************************/

extern "C" void* win_createWallet(uint8_t nettype);

extern "C" uint8_t win_initB(void* self, const char* daemon_address);
extern "C" void win_startRefresh(void* self);
extern "C" uint8_t win_storeB(void* self, const char* path);

// Returning Safex::PendingTransaction
// @warning subaddr_indices is here uint32_t. Argument will be ignored for time being because Safex doesnt support
//          subaddresses. Please be advised to pass integer value instead of initializer_list!!!!!
// Both subaddr fields will be ignored, but are kept here to avoid any serious changes in existing API.
extern "C" void* win_createTransaction(
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

extern "C" char* win_address(void* self);
extern "C" char* win_seed(void* self);
extern "C" char* win_path(void* self);
extern "C" uint8_t win_nettype(void* self);
extern "C" char* win_secretViewKey(void* self);
extern "C" char* win_publicViewKey(void* self);
extern "C" char* win_secretSpendKey(void* self);
extern "C" char* win_publicSpendKey(void* self);
extern "C" uint8_t win_setPasswordB(void* self, const char*); // @todo See if bool is valid in CAPI
extern "C" char* win_errorString(void* self);
extern "C" void win_setRefreshFromBlockeHeight(void* self, uint32_t height);
extern "C" uint32_t win_connected(void* self); // @todo Enum ConnectionStatus without default type should be uint32_t
extern "C" void win_setTrustedDaemon(void* self, uint8_t argB);
extern "C" uint8_t win_trustedDaemonB(void* self);
extern "C" uint64_t win_balanceAll(void* self);
extern "C" uint64_t win_unlockedBallanceAll(void* self);
extern "C" uint64_t win_tokenBalanceAll(void* self);
extern "C" uint64_t win_unlockedTokenBallanceAll(void* self);

extern "C" char* win_GenPaymentId();
extern "C" uint8_t win_PaymentIdValid(const char* paymentId);
extern "C" void win_SetListener(void* self, void* listener);
extern "C" void win_segregatePreForkOutputs(void* self, uint8_t segregate);
extern "C" void win_keyReuseMitigation2(void* self, uint8_t mitigation);
extern "C" char* win_IntegratedAddress(void* self, const char* paymentId);
    
extern "C" uint8_t win_static_addressValid(const char* address, uint32_t nettype);
/****************************** END WALLET API ************************************************************************/

/****************************** PENDING TRANSACTION API ***************************************************************/
extern "C" uint64_t win_pt_amount(void* self);
extern "C" uint64_t win_pt_tokenAmount(void* self);
extern "C" uint64_t win_pt_dust(void* self);
extern "C" uint64_t win_pt_fee(void* self);
extern "C" uint64_t win_pt_txCount(void* self);
// @warning Last element is nullptr!! Like
extern "C" char** win_pt_txid(void* self);
extern "C" int32_t win_pt_status(void* self);
extern "C" char* win_pt_errorString(void* self);
extern "C" uint8_t win_pt_commit(void* self);
/****************************** END PENDING TRANSACTION API ***********************************************************/


/****************************** WALLET MANAGER API ********************************************************************/
extern "C" void* win_mngf_getWalletManager();
extern "C" void win_mng_closeWallet(void* self, void* wallet, uint8_t storeB);
// @return Safex::WalletImpl
extern "C" void* win_mng_createWallet(void* self, const char* path, const char* password, const char* lang, uint32_t nettype);
// @return Safex::WalletImpl
extern "C" void* win_mng_openWallet(void* self, const char* path, const char* password, uint32_t nettype);
// @return Safex::WalletImpl
extern "C" void* win_mng_recoveryWallet(
        void* self,
        const char* path,
        const char* password,
        const char* mnemonic,
        uint32_t nettype,
        uint64_t restoreHeight);
//@return Safex::WalletManager
extern "C" uint8_t win_mng_walletExists(void* self, const char* path);
/****************************** END WALLET MANAGER API ****************************************************************/

/****************************** TRANSACTIONINFO API *******************************************************************/
extern "C" void* win_txinfo_createTransactionInfo();
extern "C" int32_t win_txinfo_direction(void* self);
extern "C" uint8_t win_txinfo_isPendingB(void* self);
extern "C" uint8_t win_txinfo_isFailedB(void* self);
extern "C" uint64_t win_txinfo_amount(void* self);
extern "C" uint64_t win_txinfo_fee(void* self);
extern "C" uint64_t win_txinfo_blockHeight(void* self);
extern "C" char* win_txinfo_label(void* self);
extern "C" char* win_txinfo_hash(void* self);
extern "C" uint64_t win_txinfo_timestamp(void* self);
extern "C" char* win_txinfo_paymentId(void* self);
// returns array of Safex::Transfers
extern "C" void* win_txinfo_transfers(void* self, uint32_t* size);
extern "C" uint64_t win_txinfo_confirmations(void* self);
extern "C" uint64_t win_txinfo_unlockTime(void* self);
extern "C" uint32_t win_txinfo_transactionType(void* self);
/****************************** END TRANSACTIONINFO API ***************************************************************/

/****************************** WALLET LISTENER API ********************************************************************/
extern "C" void* win_lstn_Create();
extern "C" void win_lstn_setMoneySpent(void* self, void(*moneySpent_)(const char*, uint64_t));
extern "C" void win_lstn_setMoneyReceived(void* self, void(*moneyReceived_)(const char*, uint64_t));
extern "C" void win_lstn_setUnconfirmedMoneyReceived(void* self, void(*unconfirmedMoneyReceived_)(const char*, uint64_t));
extern "C" void win_lstn_setTokensSpent(void* self, void(*tokensSpent_)(const char*, uint64_t));
extern "C" void win_lstn_setTokenReceived(void* self, void(*tokenReceived_)(const char*, uint64_t));
extern "C" void win_lstn_setUnconfirmedTokenReceived(void* self, void(*unconfirmedTokenReceived_)(const char*, uint64_t));
extern "C" void win_lstn_setNewBlock(void* self, void(*newBlock_)(uint64_t));
extern "C" void win_lstn_setUpdated(void* self, void(*updated_)(void));
extern "C" void win_lstn_setRefreshed(void* self, void(*refreshed_)(void));
/****************************** END WALLET LISTNER API ****************************************************************/

#endif //SAFEX_WINDOWS_WRAPPER_H

