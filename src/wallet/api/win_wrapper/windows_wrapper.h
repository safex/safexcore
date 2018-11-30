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

/****************************** WALLET API ****************************************************************************/

__declspec(dllexport) void* win_createWallet(uint8_t nettype);
__declspec(dllexport) void win_deleteWallet(void* self);

__declspec(dllexport) uint8_t win_initB(void* self, const char* daemon_address);
__declspec(dllexport) void win_startRefresh(void* self);
__declspec(dllexport) uint8_t win_storeB(void* self, const char* path);

// Returning Safex::PendingTransaction
// @warning subaddr_indices is here uint32_t. Argument will be ignored for time being because Safex doesnt support
//          subaddresses. Please be advised to pass integer value instead of initializer_list!!!!!
// Both subaddr fields will be ignored, but are kept here to avoid any serious changes in existing API.
__declspec(dllexport) void* win_createTransaction(
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

__declspec(dllexport) char* win_address(void* self);
__declspec(dllexport) char* win_seed(void* self);
__declspec(dllexport) char* win_path(void* self);
__declspec(dllexport) uint8_t win_nettype(void* self);
__declspec(dllexport) char* win_secretViewKey(void* self);
__declspec(dllexport) char* win_publicViewKey(void* self);
__declspec(dllexport) char* win_secretSpendKey(void* self);
__declspec(dllexport) char* win_publicSpendKey(void* self);
__declspec(dllexport) uint8_t win_setPasswordB(void* self, const char*); // @todo See if bool is valid in CAPI
__declspec(dllexport) char* win_errorString(void* self);
__declspec(dllexport) void win_setRefreshFromBlockeHeight(void* self, uint32_t height);
__declspec(dllexport) uint32_t win_connected(void* self); // @todo Enum ConnectionStatus without default type should be uint32_t
__declspec(dllexport) void win_setTrustedDaemon(void* self, uint8_t argB);
__declspec(dllexport) uint8_t win_trustedDaemonB(void* self);
__declspec(dllexport) uint64_t win_balanceAll(void* self);
__declspec(dllexport) uint64_t win_unlockedBallanceAll(void* self);
__declspec(dllexport) uint64_t win_tokenBalanceAll(void* self);
__declspec(dllexport) uint64_t win_unlockedTokenBallanceAll(void* self);

__declspec(dllexport) char* win_GenPaymentId();
__declspec(dllexport) uint8_t win_PaymentIdValid(const char* paymentId);
__declspec(dllexport) void win_SetListener(void* self, void* listener);
__declspec(dllexport) void win_segregatePreForkOutputs(void* self, uint8_t segregate);
__declspec(dllexport) void win_keyReuseMitigation2(void* self, uint8_t mitigation);
__declspec(dllexport) char* win_IntegratedAddress(void* self, const char* paymentId);
    
__declspec(dllexport) uint8_t win_static_addressValid(const char* address, uint32_t nettype);
/****************************** END WALLET API ************************************************************************/

/****************************** PENDING TRANSACTION API ***************************************************************/
__declspec(dllexport) void* win_pt_create(void* wallet);
__declspec(dllexport) void win_pt_delete(void* self);
__declspec(dllexport) uint64_t win_pt_amount(void* self);
__declspec(dllexport) uint64_t win_pt_tokenAmount(void* self);
__declspec(dllexport) uint64_t win_pt_dust(void* self);
__declspec(dllexport) uint64_t win_pt_fee(void* self);
__declspec(dllexport) uint64_t win_pt_txCount(void* self);
// @warning Last element is nullptr!! Like
__declspec(dllexport) char** win_pt_txid(void* self);
__declspec(dllexport) int32_t win_pt_status(void* self);
__declspec(dllexport) char* win_pt_errorString(void* self);
__declspec(dllexport) uint8_t win_pt_commit(void* self);
/****************************** END PENDING TRANSACTION API ***********************************************************/


/****************************** WALLET MANAGER API ********************************************************************/
__declspec(dllexport) void* win_mngf_getWalletManager();
__declspec(dllexport) void win_mng_closeWallet(void* self, void* wallet, uint8_t storeB);
// @return Safex::WalletImpl
__declspec(dllexport) void* win_mng_createWallet(void* self, const char* path, const char* password, const char* lang, uint32_t nettype);
// @return Safex::WalletImpl
__declspec(dllexport) void* win_mng_openWallet(void* self, const char* path, const char* password, uint32_t nettype);
// @return Safex::WalletImpl
__declspec(dllexport) void* win_mng_recoveryWallet(
        void* self,
        const char* path,
        const char* password,
        const char* mnemonic,
        uint32_t nettype,
        uint64_t restoreHeight);
//@return Safex::WalletManager
__declspec(dllexport) uint8_t win_mng_walletExists(void* self, const char* path);
/****************************** END WALLET MANAGER API ****************************************************************/

/****************************** TRANSACTIONINFO API *******************************************************************/
__declspec(dllexport) void* win_txinfo_createTransactionInfo();
__declspec(dllexport) void win_txinfo_deleteTransactionInfo(void* self);
__declspec(dllexport) int32_t win_txinfo_direction(void* self);
__declspec(dllexport) uint8_t win_txinfo_isPendingB(void* self);
__declspec(dllexport) uint8_t win_txinfo_isFailedB(void* self);
__declspec(dllexport) uint64_t win_txinfo_amount(void* self);
__declspec(dllexport) uint64_t win_txinfo_fee(void* self);
__declspec(dllexport) uint64_t win_txinfo_blockHeight(void* self);
__declspec(dllexport) char* win_txinfo_label(void* self);
__declspec(dllexport) char* win_txinfo_hash(void* self);
__declspec(dllexport) uint64_t win_txinfo_timestamp(void* self);
__declspec(dllexport) char* win_txinfo_paymentId(void* self);
// returns array of Safex::Transfers
__declspec(dllexport) void* win_txinfo_transfers(void* self, uint32_t* size);
__declspec(dllexport) uint64_t win_txinfo_confirmations(void* self);
__declspec(dllexport) uint64_t win_txinfo_unlockTime(void* self);
__declspec(dllexport) uint32_t win_txinfo_transactionType(void* self);
/****************************** END TRANSACTIONINFO API ***************************************************************/

/****************************** WALLET LISTENER API ********************************************************************/
__declspec(dllexport) void* win_lstn_Create();
__declspec(dllexport) void win_lstn_setMoneySpent(void* self, void(*moneySpent_)(const char*, uint64_t));
__declspec(dllexport) void win_lstn_setMoneyReceived(void* self, void(*moneyReceived_)(const char*, uint64_t));
__declspec(dllexport) void win_lstn_setUnconfirmedMoneyReceived(void* self, void(*unconfirmedMoneyReceived_)(const char*, uint64_t));
__declspec(dllexport) void win_lstn_setTokensSpent(void* self, void(*tokensSpent_)(const char*, uint64_t));
__declspec(dllexport) void win_lstn_setTokenReceived(void* self, void(*tokenReceived_)(const char*, uint64_t));
__declspec(dllexport) void win_lstn_setUnconfirmedTokenReceived(void* self, void(*unconfirmedTokenReceived_)(const char*, uint64_t));
__declspec(dllexport) void win_lstn_setNewBlock(void* self, void(*newBlock_)(uint64_t));
__declspec(dllexport) void win_lstn_setUpdated(void* self, void(*updated_)(void));
__declspec(dllexport) void win_lstn_setRefreshed(void* self, void(*refreshed_)(void));
/****************************** END WALLET LISTNER API ****************************************************************/

#endif //SAFEX_WINDOWS_WRAPPER_H

