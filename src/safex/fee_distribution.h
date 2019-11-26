//
// Created by amarko on 13.3.19..
//

#ifndef SAFEX_FEE_DISTRIBUTION_H
#define SAFEX_FEE_DISTRIBUTION_H

#include <cstdint>

namespace safex
{

  uint64_t calculate_token_interest(uint64_t locked_token_output_index, uint64_t end_block, uint64_t locked_token_amount);


}


#endif //SAFEX_FEE_DISTRIBUTION_H
