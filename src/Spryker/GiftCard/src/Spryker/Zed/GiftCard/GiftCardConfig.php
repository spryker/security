<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\GiftCard;

use Spryker\Zed\Kernel\AbstractBundleConfig;

class GiftCardConfig extends AbstractBundleConfig
{
    /**
     * @return string
     */
    public function getCodePrefix()
    {
        return 'GC';
    }

    /**
     * @return string
     */
    public function getCodeSuffix()
    {
        return date('y');
    }

    /**
     * @return int
     */
    public function getCodeRandomPartLength()
    {
        return 8;
    }

    /**
     * @return array
     */
    public function getGiftCardMethodBlacklist()
    {
        return [];
    }
}
