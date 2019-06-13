<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Glossary\Business\Reader;

interface TranslationReaderInterface
{
    /**
     * @param string $glossaryKey
     * @param \Generated\Shared\Transfer\LocaleTransfer[] $localeTransfers
     *
     * @return array
     */
    public function getTranslationsByGlossaryKeyAndLocaleTransfers(string $glossaryKey, array $localeTransfers): array;
}
