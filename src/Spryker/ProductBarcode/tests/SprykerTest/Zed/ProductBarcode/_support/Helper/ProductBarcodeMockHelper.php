<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\ProductBarcode\Helper;

use Codeception\Module;
use Codeception\Util\Stub;
use Generated\Shared\Transfer\BarcodeResponseTransfer;
use Spryker\Service\BarcodeExtension\Dependency\Plugin\BarcodeGeneratorPluginInterface;

class ProductBarcodeMockHelper extends Module
{
    protected const GENERATED_ENCODING = 'data:image/png;base64';

    /**
     * @return \PHPUnit\Framework\MockObject\MockObject|\Spryker\Service\BarcodeExtension\Dependency\Plugin\BarcodeGeneratorPluginInterface
     */
    public function getBarcodePluginMock(): BarcodeGeneratorPluginInterface
    {
        return Stub::makeEmpty(BarcodeGeneratorPluginInterface::class, [
            'generate' => function (string $text): BarcodeResponseTransfer {
                return (new BarcodeResponseTransfer())
                    ->setCode($text)
                    ->setEncoding(static::GENERATED_ENCODING);
            },
        ]);
    }
}
