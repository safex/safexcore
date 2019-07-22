//
// Created by stefan on 29.11.18..
//

#ifndef SAFEX_WINDOWS_WALLET_LISTENER_H
#define SAFEX_WINDOWS_WALLET_LISTENER_H

#include "../wallet_api.h"

struct WinWalletListener : public Safex::WalletListener
{
    void(*moneySpent_)(void*, const char*, uint64_t);
    void(*moneyReceived_)(void*,const char*, uint64_t);
    void(*unconfirmedMoneyReceived_)(void*,const char*, uint64_t);
    void(*tokensSpent_)(void*,const char*, uint64_t);
    void(*tokenReceived_)(void*,const char*, uint64_t);
    void(*unconfirmedTokenReceived_)(void*,const char*, uint64_t);
    void(*newBlock_)(void*,uint64_t);
    void(*updated_)(void*);
    void(*refreshed_)(void*);

    WinWalletListener(void* up) : ptr_to_up(up) {

    }

    virtual ~WinWalletListener() {

    };
    virtual void moneySpent(const std::string &txId, uint64_t amount) {
        //(*moneySpent_)(ptr_to_up, txId.c_str(), amount);
    }
    virtual void moneyReceived(const std::string &txId, uint64_t amount) {
        //(*moneyReceived_)(ptr_to_up, txId.c_str(), amount);
    }
    virtual void unconfirmedMoneyReceived(const std::string &txId, uint64_t amount) {
        //(*unconfirmedMoneyReceived_)(ptr_to_up, txId.c_str(), amount);
    }
    virtual void tokensSpent(const std::string &txId, uint64_t token_amount) {
        //(*tokensSpent_)(ptr_to_up, txId.c_str(), token_amount);
    }
    virtual void tokensReceived(const std::string &txId, uint64_t token_amount) {
        //(*tokenReceived_)(ptr_to_up, txId.c_str(), token_amount);
    }
    virtual void unconfirmedTokensReceived(const std::string &txId, uint64_t token_amount) {
        //(*unconfirmedMoneyReceived_)(ptr_to_up, txId.c_str(), token_amount);
    }
    virtual void newBlock(uint64_t height) {
        //(*newBlock_)(ptr_to_up, height);
    }
    virtual void updated() {
        //(*updated_)(ptr_to_up );
    }

    virtual void refreshed() {
        (*refreshed_)(ptr_to_up);
    }

private:
    void* ptr_to_up;
};


#endif //SAFEX_WINDOWS_WALLET_LISTENER_H
