<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\QuoteApproval\Plugin\Permission;

use Spryker\Shared\PermissionExtension\Dependency\Plugin\ExecutablePermissionPluginInterface;

class ApproveQuotePermissionPlugin implements ExecutablePermissionPluginInterface
{
    public const KEY = 'ApproveQuotePermissionPlugin';

    protected const FIELD_MULTI_CURRENCY = 'multi_currency';

    /**
     * {@inheritdoc}
     * - Checks if approver is allowed to approve order with cent amount up to some value for specific currency, provided in configuration.
     * - Returns false, if quote is not provided.
     * - Returns false, if configuration does not have cent amount for specific currency set.
     *
     * @param array $configuration
     * @param \Generated\Shared\Transfer\QuoteTransfer|null $quoteTransfer
     *
     * @return bool
     */
    public function can(array $configuration, $quoteTransfer = null): bool
    {
        if ($quoteTransfer === null) {
            return false;
        }

        $centAmount = $quoteTransfer->getTotals()->getGrandTotal();
        $currencyCode = $quoteTransfer->getCurrency()->getCode();

        if (!isset($configuration[static::FIELD_MULTI_CURRENCY][$currencyCode])) {
            return false;
        }

        if ($configuration[static::FIELD_MULTI_CURRENCY][$currencyCode] >= (int)$centAmount) {
            return false;
        }

        return true;
    }

    /**
     * @return string[]
     */
    public function getConfigurationSignature(): array
    {
        return [
            static::FIELD_MULTI_CURRENCY => static::CONFIG_FIELD_TYPE_MULTI_CURRENCY,
        ];
    }

    /**
     * @return string
     */
    public function getKey(): string
    {
        return static::KEY;
    }
}
