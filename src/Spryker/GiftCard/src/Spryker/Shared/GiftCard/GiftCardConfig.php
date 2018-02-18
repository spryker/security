<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\GiftCard;

use Spryker\Shared\Kernel\AbstractBundleConfig;

class GiftCardConfig extends AbstractBundleConfig
{
    const ERROR_GIFT_CARD_ALREADY_USED = 407;
    const ERROR_GIFT_CARD_AMOUNT_TOO_HIGH = 408;
    const ERROR_GIFT_CARD_WRONG_CURRENCY = 409;
}
