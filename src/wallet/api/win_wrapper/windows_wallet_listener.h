//
// Created by stefan on 29.11.18..
//

#ifndef SAFEX_WINDOWS_WALLET_LISTENER_H
#define SAFEX_WINDOWS_WALLET_LISTENER_H

#include "../wallet_api.h"

struct WinWalletListener : public Safex::WalletListener
{
    void(*moneySpent_)(const char*, uint64_t);
    void(*moneyReceived_)(const char*, uint64_t);
    void(*unconfirmedMoneyReceived_)(const char*, uint64_t);
    void(*tokensSpent_)(const char*, uint64_t);
    void(*tokenReceived_)(const char*, uint64_t);
    void(*unconfirmedTokenReceived_)(const char*, uint64_t);
    void(*newBlock_)(uint64_t);
    void(*updated_)(void);
    void(*refreshed_)(void);


    virtual ~WinWalletListener() {

    };
    virtual void moneySpent(const std::string &txId, uint64_t amount) {
        (*moneySpent_)(txId.c_str(), amount);
    }
    virtual void moneyReceived(const std::string &txId, uint64_t amount) {
        (*moneyReceived_)(txId.c_str(), amount);
    }
    virtual void unconfirmedMoneyReceived(const std::string &txId, uint64_t amount) {
        (*unconfirmedMoneyReceived_)(txId.c_str(), amount);
    }
    virtual void tokensSpent(const std::string &txId, uint64_t token_amount) {
        (*tokensSpent_)(txId.c_str(), token_amount);
    }
    virtual void tokensReceived(const std::string &txId, uint64_t token_amount) {
        (*tokenReceived_)(txId.c_str(), token_amount);
    }
    virtual void unconfirmedTokensReceived(const std::string &txId, uint64_t token_amount) {
        (*unconfirmedMoneyReceived_)(txId.c_str(), token_amount);
    }
    virtual void newBlock(uint64_t height) {
        (*newBlock_)(height);
    }
    virtual void updated() {
        (*updated_)();
    }

    virtual void refreshed() {
        (*refreshed_)();
    }
};


#endif //SAFEX_WINDOWS_WALLET_LISTENER_H
